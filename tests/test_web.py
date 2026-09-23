"""The web console and the machine doors, over HTTP."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

import pytest
from fastapi.testclient import TestClient

from airlock.config import load_control
from airlock.control.app import create_app
from airlock.control.service import ControlPlane
from airlock.crypto import PROFILE_HEADER
from tests.conftest import PASSWORD, fenced, plan_doc, signed


@pytest.fixture
def plane(config_dict: dict[str, Any], env: dict[str, str]) -> ControlPlane:
    return ControlPlane(load_control(config_dict, env))


@pytest.fixture
def client(plane: ControlPlane) -> TestClient:
    return TestClient(create_app(plane.config, plane=plane, run_loop=False), follow_redirects=False)


def login(client: TestClient) -> str:
    response = client.post("/login", data={"password": PASSWORD})
    assert response.status_code == 303 and response.headers["location"] == "/"
    return csrf_of(client.get("/").text)


def csrf_of(html: str) -> str:
    match = re.search(r'name="csrf" value="([0-9a-f]+)"', html)
    assert match, "no csrf token on the page"
    return match.group(1)


def plan_ready(plane: ControlPlane, title: str = "API 5xx") -> str:
    work_id = plane.manual_signal(title, "7% errors").body["work_id"]
    plane.db.execute("UPDATE work_items SET state = 'investigating' WHERE id = ?", [work_id])
    assert (
        plane.receive_result("infra", {"work_id": work_id, "text": fenced(plan_doc())}).body["status"] == "plan_ready"
    )
    return str(work_id)


def test_everything_behind_the_login(client: TestClient) -> None:
    for path in ("/", "/ledger", "/events", "/outbox", "/work/nope"):
        response = client.get(path)
        assert response.status_code == 303 and response.headers["location"] == "/login"
    assert client.post("/signals", data={"title": "x"}).status_code == 303


def test_a_wrong_password_is_recorded_and_throttled(client: TestClient, plane: ControlPlane) -> None:
    for _ in range(5):
        assert "密码不对" in client.post("/login", data={"password": "nope"}).text
    assert "尝试次数过多" in client.post("/login", data={"password": PASSWORD}).text
    assert [e["kind"] for e in plane.ledger.entries()].count("login.failed") == 5


def test_the_session_cookie_is_strict_and_http_only(client: TestClient) -> None:
    response = client.post("/login", data={"password": PASSWORD})
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_approving_from_the_page(client: TestClient, plane: ControlPlane) -> None:
    work_id = plan_ready(plane)
    csrf = login(client)
    index = client.get("/").text
    assert "等你决定" in index and f"/work/{work_id}" in index

    page = client.get(f"/work/{work_id}").text
    current = plane.detail(work_id)["current"]  # type: ignore[index]
    assert f'name="plan_hash" value="{current["plan_hash"]}"' in page
    assert "echo restarting api" in page and "批准 v1 并执行" in page

    form = {"version": "1", "plan_hash": current["plan_hash"]}
    assert client.post(f"/work/{work_id}/approve", data=form).status_code == 403
    assert client.post(f"/work/{work_id}/approve", data={**form, "csrf": "0" * 64}).status_code == 403
    stale = client.post(f"/work/{work_id}/approve", data={**form, "plan_hash": "1" * 64, "csrf": csrf})
    assert stale.status_code == 303 and plane.work(work_id)["state"] == "plan_ready"  # type: ignore[index]
    assert "the plan changed" in client.get(stale.headers["location"]).text

    done = client.post(f"/work/{work_id}/approve", data={**form, "csrf": csrf})
    assert done.status_code == 303 and plane.work(work_id)["state"] == "approved"  # type: ignore[index]
    approval = plane.db.one("SELECT approver, via FROM approvals")
    assert approval == {"approver": "operator", "via": "web"}
    assert "撤回批准" in client.get(f"/work/{work_id}").text


def test_messages_reject_and_manual_signals(client: TestClient, plane: ControlPlane) -> None:
    work_id = plan_ready(plane)
    csrf = login(client)
    client.post(f"/work/{work_id}/message", data={"text": "drain first", "csrf": csrf})
    assert plane.work(work_id)["state"] == "queued"  # type: ignore[index]

    other = plan_ready(plane, "second")
    client.post(f"/work/{other}/reject", data={"reason": "not now", "csrf": csrf})
    assert plane.work(other)["state"] == "rejected"  # type: ignore[index]

    created = client.post("/signals", data={"title": "look at the disk", "body": "", "csrf": csrf})
    assert created.status_code == 303 and created.headers["location"].startswith("/work/")
    for path in ("/ledger", "/events", "/outbox", created.headers["location"]):
        assert client.get(path).status_code == 200


def test_untrusted_text_is_escaped(client: TestClient, plane: ControlPlane) -> None:
    work_id = plane.manual_signal("<script>alert(1)</script>", "<img src=x onerror=alert(1)>").body["work_id"]
    login(client)
    page = client.get(f"/work/{work_id}").text
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
    assert "<img src=x" not in page


def test_investigator_doors_need_the_profile_signature(
    client: TestClient, plane: ControlPlane, env: dict[str, str]
) -> None:
    work_id = plane.manual_signal("t", "b").body["work_id"]
    plane.db.execute("UPDATE work_items SET state = 'investigating' WHERE id = ?", [work_id])
    payload = {"work_id": work_id, "text": fenced(plan_doc())}

    body, headers = signed(env["T_INFRA"], payload)
    assert client.post("/v1/investigations/result", content=body, headers=headers).status_code == 401
    body, headers = signed(env["T_CODE"], payload, **{PROFILE_HEADER: "infra"})
    assert client.post("/v1/investigations/result", content=body, headers=headers).status_code == 401
    body, headers = signed(env["T_CODE"], payload, **{PROFILE_HEADER: "code"})
    assert client.post("/v1/investigations/result", content=body, headers=headers).status_code == 403
    body, headers = signed(env["T_INFRA"], payload, **{PROFILE_HEADER: "infra"})
    response = client.post("/v1/investigations/result", content=body, headers=headers)
    assert response.status_code == 200 and response.json()["status"] == "plan_ready"


def test_the_launcher_door_and_the_adapter_door(client: TestClient, plane: ControlPlane, env: dict[str, str]) -> None:
    work_id = plan_ready(plane)
    current = plane.detail(work_id)["current"]  # type: ignore[index]
    decision = {
        "work_id": work_id,
        "decision": "approve",
        "version": 1,
        "plan_hash": current["plan_hash"],
        "platform_user": "u-123",
    }
    body, headers = signed(env["T_HOOKS"], decision)
    assert client.post("/v1/adapters/chat/decision", content=body, headers=headers).status_code == 401
    body, headers = signed(env["T_CHAT"], decision)
    assert client.post("/v1/adapters/chat/decision", content=body, headers=headers).status_code == 200
    assert client.post("/v1/adapters/nope/decision", content=body, headers=headers).status_code == 404

    body, headers = signed(env["T_CHAT"], {"approval_id": "x", "plan_hash": "y"})
    assert client.post("/v1/runs/result", content=body, headers=headers).status_code == 401
    body, headers = signed(env["T_LAUNCHER"], {"approval_id": "x", "plan_hash": "y"})
    assert client.post("/v1/runs/result", content=body, headers=headers).status_code == 404


def test_the_intake_door_over_http(client: TestClient, env: dict[str, str]) -> None:
    payload = {
        "action": "labeled",
        "label": {"name": "airlock"},
        "issue": {"title": "Slow checkout", "body": "", "html_url": "", "number": 3},
        "repository": {"full_name": "acme/shop"},
    }
    body = json.dumps(payload).encode()
    signature = "sha256=" + hmac.new(env["T_GITHUB"].encode(), body, hashlib.sha256).hexdigest()
    headers = {"X-Hub-Signature-256": signature, "X-GitHub-Event": "issues", "Content-Type": "application/json"}
    response = client.post("/v1/intake/github", content=body, headers=headers)
    assert response.status_code == 202 and response.json()["outcome"] == "accepted"
    assert (
        client.post(
            "/v1/intake/github", content=body, headers={**headers, "X-Hub-Signature-256": "sha256=0"}
        ).status_code
        == 401
    )
    assert client.get("/healthz").json()["ok"] is True
