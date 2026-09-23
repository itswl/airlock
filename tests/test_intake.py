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


def test_an_alert_that_keeps_firing_keeps_joining(plane: ControlPlane, env: dict[str, str]) -> None:
    first = plane.intake("alerts", *alert(env, plane)).body["work_id"]
    for _ in range(3):
        plane.clock.now += 500  # type: ignore[attr-defined]  # each gap is inside the 600s window, the total is not
        assert plane.intake("alerts", *alert(env, plane)).body == {"outcome": "duplicate", "work_id": first}
    assert plane.work(first)["signals"] == 4  # type: ignore[index]


def test_a_repeat_after_the_work_item_ended_continues_it(plane: ControlPlane, env: dict[str, str]) -> None:
    first = plane.intake("alerts", *alert(env, plane)).body["work_id"]
    plane.close(first, via="web")
    plane.clock.now += 3600  # type: ignore[attr-defined]
    again = plane.intake("alerts", *alert(env, plane))
    assert again.status == 202 and again.body["outcome"] == "continued" and again.body["continues"] == first
    sequel = plane.work(again.body["work_id"])
    assert sequel["continues"] == first and sequel["session_hint"] == f"fork:{first}"  # type: ignore[index]
    plane.close(sequel["id"], via="web")  # type: ignore[index]
    plane.clock.now += 21601  # type: ignore[attr-defined]
    later = plane.intake("alerts", *alert(env, plane)).body
    assert later["outcome"] == "accepted" and "continues" not in later


def test_different_alerts_never_continue_each_other(plane: ControlPlane, env: dict[str, str]) -> None:
    first = plane.intake("alerts", *alert(env, plane, fingerprint="fp1")).body["work_id"]
    plane.close(first, via="web")
    other = plane.intake("alerts", *alert(env, plane, fingerprint="fp2")).body
    assert other["outcome"] == "accepted" and "continues" not in other


def test_a_failed_investigation_is_not_worth_continuing(plane: ControlPlane, env: dict[str, str]) -> None:
    first = plane.intake("alerts", *alert(env, plane)).body["work_id"]
    plane.db.execute("UPDATE work_items SET state = 'error', concluded_at = NULL WHERE id = ?", [first])
    assert plane.intake("alerts", *alert(env, plane)).body["outcome"] == "accepted"


def test_an_open_report_is_superseded_by_its_sequel(plane: ControlPlane, env: dict[str, str]) -> None:
    first = plane.intake("alerts", *alert(env, plane)).body["work_id"]
    plane._set(first, state="answered")
    plane.clock.now += 601  # type: ignore[attr-defined]  # quiet longer than the merge window
    again = plane.intake("alerts", *alert(env, plane)).body
    assert again["outcome"] == "continued" and again["continues"] == first
    old = plane.work(first)
    assert old["state"] == "closed" and again["work_id"] in old["note"]  # type: ignore[index]


def test_split_gives_each_alert_its_own_work_item(config_dict: dict[str, Any], env: dict[str, str]) -> None:
    config = dict(config_dict)
    config["sources"] = [
        *config_dict["sources"],
        {
            "name": "am",
            "verify": "bearer",
            "secret_env": "T_CI",
            "split": "alerts",
            "accept": [{"when": {"status": "firing"}}],
            "map": {
                "title": "{labels.alertname}",
                "body": "{annotations.summary}",
                "key": "{labels.alertname}|{labels.service}",
            },
        },
    ]
    plane = ControlPlane(load_control(config, env), clock=Clock())
    group = {
        "groupKey": '{}:{cluster="prod"}',
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "HighErrorRate", "service": "api"},
                "annotations": {"summary": "5xx"},
            },
            {
                "status": "firing",
                "labels": {"alertname": "PoolExhausted", "service": "api"},
                "annotations": {"summary": "10/10"},
            },
            {
                "status": "resolved",
                "labels": {"alertname": "DiskFull", "service": "db"},
                "annotations": {"summary": "ok"},
            },
        ],
    }
    headers = {"Authorization": f"Bearer {env['T_CI']}"}
    first = plane.intake("am", headers, json.dumps(group).encode())
    assert first.status == 202 and first.body["outcome"] == "split"
    assert [s["outcome"] for s in first.body["signals"]] == ["accepted", "accepted"]
    titles = sorted(w["title"] for w in plane.list_work())
    assert titles == ["HighErrorRate", "PoolExhausted"]
    again = plane.intake("am", headers, json.dumps(group).encode())
    assert again.status == 200 and [s["outcome"] for s in again.body["signals"]] == ["duplicate", "duplicate"]
