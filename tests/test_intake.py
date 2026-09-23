from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import pytest

from airlock.config import load_control
from airlock.control.service import ControlPlane
from airlock.crypto import sign


class Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def plane(config_dict: dict[str, Any], env: dict[str, str]) -> ControlPlane:
    return ControlPlane(load_control(config_dict, env), clock=Clock())


def github(env: dict[str, str], payload: dict[str, Any], event: str = "issues") -> tuple[dict[str, str], bytes]:
    body = json.dumps(payload).encode()
    signature = "sha256=" + hmac.new(env["T_GITHUB"].encode(), body, hashlib.sha256).hexdigest()
    return {"X-Hub-Signature-256": signature, "X-GitHub-Event": event}, body


def issue(action: str = "labeled", label: str = "airlock", number: int = 7) -> dict[str, Any]:
    return {
        "action": action,
        "label": {"name": label},
        "issue": {
            "title": "Checkout is slow",
            "body": "p99 is 4s",
            "html_url": "https://example.invalid/7",
            "number": number,
        },
        "repository": {"full_name": "acme/shop"},
    }


def alert(
    env: dict[str, str], plane: ControlPlane, status: str = "firing", fingerprint: str = "fp1"
) -> tuple[dict[str, str], bytes]:
    body = json.dumps(
        {
            "status": status,
            "alertname": "HighErrorRate",
            "summary": "5xx over 5%",
            "description": "api",
            "fingerprint": fingerprint,
        }
    ).encode()
    return sign(env["T_ALERTS"], body, now=plane.clock()), body


def test_a_signed_github_event_becomes_work_for_the_routed_investigator(
    plane: ControlPlane, env: dict[str, str]
) -> None:
    headers, body = github(env, issue())
    outcome = plane.intake("github", headers, body)
    assert outcome.status == 202
    work = plane.work(outcome.body["work_id"])
    assert work is not None
    assert (work["investigator"], work["state"], work["key"], work["title"]) == (
        "code",
        "queued",
        "acme/shop#7",
        "Checkout is slow",
    )
    assert work["labels"] == ["github"]
    assert [e["kind"] for e in plane.ledger.entries(work_id=work["id"])] == ["work.created"]
    assert plane.db.one("SELECT event FROM outbox")["event"] == "work.created"


def test_a_bad_signature_is_refused_and_recorded(plane: ControlPlane, env: dict[str, str]) -> None:
    headers, body = github(env, issue())
    headers["X-Hub-Signature-256"] = "sha256=" + "0" * 64
    assert plane.intake("github", headers, body).status == 401
    assert plane.db.one("SELECT outcome FROM events")["outcome"] == "rejected"
    assert plane.ledger.entries()[0]["kind"] == "signal.rejected"
    assert plane.list_work() == []


def test_events_no_rule_accepts_are_filtered(plane: ControlPlane, env: dict[str, str]) -> None:
    for payload, event in [(issue(action="opened"), "issues"), (issue(label="bug"), "issues"), (issue(), "push")]:
        headers, body = github(env, payload, event)
        assert plane.intake("github", headers, body).body == {"outcome": "filtered"}
    assert plane.list_work() == []


def test_a_repeat_inside_the_window_joins_the_open_work_item(plane: ControlPlane, env: dict[str, str]) -> None:
    first = plane.intake("alerts", *alert(env, plane)).body["work_id"]
    plane.clock.now += 60  # type: ignore[attr-defined]
    again = plane.intake("alerts", *alert(env, plane))
    assert again.body == {"outcome": "duplicate", "work_id": first}
    assert [m["author"] for m in plane.detail(first)["messages"]] == ["source:alerts"]  # type: ignore[index]
    plane.clock.now += 700  # type: ignore[attr-defined]
    later = plane.intake("alerts", *alert(env, plane))
    assert later.status == 202 and later.body["work_id"] != first


def test_a_finished_work_item_does_not_swallow_the_next_signal(plane: ControlPlane, env: dict[str, str]) -> None:
    first = plane.intake("alerts", *alert(env, plane)).body["work_id"]
    plane.close(first, via="web")
    assert plane.intake("alerts", *alert(env, plane)).body["work_id"] != first


def test_bearer_sources_and_the_fallback_route(plane: ControlPlane, env: dict[str, str]) -> None:
    body = json.dumps({"title": "nightly build red", "body": "tests failed"}).encode()
    assert plane.intake("ci", {"Authorization": "Bearer nope"}, body).status == 401
    outcome = plane.intake("ci", {"Authorization": f"Bearer {env['T_CI']}"}, body)
    assert plane.work(outcome.body["work_id"])["investigator"] == "infra"  # type: ignore[index]


def test_garbage_and_unknown_sources(plane: ControlPlane, env: dict[str, str]) -> None:
    assert plane.intake("nope", {}, b"{}").status == 404
    headers = {"Authorization": f"Bearer {env['T_CI']}"}
    assert plane.intake("ci", headers, b"not json").status == 400
    assert plane.intake("ci", headers, b"[1, 2]").status == 400
    assert plane.intake("ci", headers, b"x" * (1_048_577)).status == 400


def test_a_resolved_alert_is_filtered(plane: ControlPlane, env: dict[str, str]) -> None:
    assert plane.intake("alerts", *alert(env, plane, status="resolved")).body == {"outcome": "filtered"}
