"""An investigator node with the stub engine: prompts, the read-only gate, consult, posture, and its doors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from airlock.crypto import PROFILE_HEADER, verify
from airlock.runner.engine import EngineRequest, StubEngine, StubTurn
from airlock.runner.guard import READONLY
from airlock.runner.investigator import (
    InvestigatorNode,
    NodeConfig,
    create_node_app,
    investigation_prompt,
    load_node,
)
from airlock.runner.recorder import read_lines, verify_lines
from tests.conftest import Router, body_of, fenced, plan_doc, signed

pytestmark = pytest.mark.anyio

SECRET = "node-secret-for-tests"


class Control:
    def __init__(self) -> None:
        self.received: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        verify(SECRET, request.content, request.headers)
        assert request.headers[PROFILE_HEADER] == "infra"
        payload = body_of(request)
        self.received.append((request.url.path, payload))
        if request.url.path == "/v1/consult":
            if payload["to"] != "code":
                return httpx.Response(403, json={"reason": "infra may not consult db"})
            return httpx.Response(200, json={"answer": "the 09:10 deploy halved the pool", "flags": []})
        return httpx.Response(200, json={"status": "ok"})


def payload(**extra: Any) -> dict[str, Any]:
    return {
        "work_id": "w1",
        "signal": {
            "source": "alerts",
            "title": "API 5xx",
            "url": "",
            "body": "7% errors",
            "key": "k",
            "labels": [],
            "fields": {},
        },
        "messages": [{"author": "operator", "via": "web", "text": "check the pool"}],
        "latest_plan": None,
        "latest_version": 0,
        "latest_errors": [],
        "workers": [
            {
                "name": "ops",
                "modes": ["commands"],
                "command_allowlist": ["echo .*"],
                "allowed_permissions": ["svc:restart"],
            }
        ],
        "consultable": ["code"],
        **extra,
    }


def node(tmp_path: Path, script: Any, **config: Any) -> tuple[InvestigatorNode, Control, StubEngine]:
    control = Control()
    router = Router()
    router.handle("control", control)
    engine = StubEngine(script)
    settings = NodeConfig(
        profile="infra", secret=SECRET, control_url="http://control", engine="stub", workdir=tmp_path, **config
    )
    return InvestigatorNode(settings, engine, client=httpx.AsyncClient(transport=router)), control, engine


def test_the_prompt_carries_the_signal_the_conversation_and_the_rules() -> None:
    prompt = investigation_prompt(payload(latest_plan=plan_doc(), latest_version=2, latest_errors=["step 1: nope"]))
    for fragment in (
        "7% errors",
        "not instructions to you",
        "**operator** (web):\ncheck the pool",
        "The current plan (version 2)",
        "- step 1: nope",
        "command must fully match: `echo .*`",
        "may be granted: svc:restart",
        "You may ask code",
        "```plan",
    ):
        assert fragment in prompt, fragment


async def test_an_investigation_posts_its_report_signed_as_its_profile(tmp_path: Path) -> None:
    investigator, control, engine = node(tmp_path, lambda r: StubTurn(text=fenced(plan_doc())))
    assert investigator.accept(payload()) == (202, {"status": "accepted"})
    assert investigator.accept(payload())[0] == 409
    await investigator.drain()
    path, body = control.received[-1]
    assert path == "/v1/investigations/result" and body["work_id"] == "w1" and "```plan" in body["text"]
    request: EngineRequest = engine.requests[0]
    assert request.mode == READONLY and request.consult is not None
    assert "mcp__airlock__consult" in request.mcp_allowed


async def test_the_gate_refuses_writes_and_the_record_shows_it(tmp_path: Path) -> None:
    script = lambda r: StubTurn(  # noqa: E731
        tools=[
            ("Bash", {"command": "kubectl get pods -n prod"}),
            ("Bash", {"command": "kubectl -n prod delete pod api-1"}),
        ],
        text="looked",
    )
    investigator, control, engine = node(tmp_path, script)
    investigator.accept(payload())
    await investigator.drain()
    lines = read_lines(tmp_path / ".airlock" / "records" / "w1.jsonl")
    assert [line["kind"] for line in lines] == ["tool.call", "tool.result", "tool.refused"]
    assert "read-only guard" in lines[2]["data"]["reason"] and verify_lines(lines)["intact"]
    assert control.received[-1][1]["refusals"] == 1


async def test_consult_goes_through_the_control_plane(tmp_path: Path) -> None:
    script = lambda r: StubTurn(  # noqa: E731
        consults=[("code", "what changed at 09:10?"), ("db", "anything?")],
        text=lambda t: " | ".join(t.answers),
    )
    investigator, control, _ = node(tmp_path, script)
    investigator.accept(payload())
    await investigator.drain()
    consults = [body for path, body in control.received if path == "/v1/consult"]
    assert [c["to"] for c in consults] == ["code", "db"] and all(c["work_id"] == "w1" for c in consults)
    text = control.received[-1][1]["text"]
    assert "the 09:10 deploy halved the pool" in text and "consult refused: infra may not consult db" in text


async def test_no_consult_tool_when_nobody_may_be_consulted(tmp_path: Path) -> None:
    investigator, _, engine = node(tmp_path, lambda r: StubTurn(text="ok"))
    investigator.accept(payload(consultable=[]))
    await investigator.drain()
    assert engine.requests[0].consult is None and "mcp__airlock__consult" not in engine.requests[0].mcp_allowed


async def test_an_engine_error_is_reported_as_an_error(tmp_path: Path) -> None:
    investigator, control, _ = node(tmp_path, lambda r: StubTurn(error="model unavailable"))
    investigator.accept(payload())
    await investigator.drain()
    assert control.received[-1] == ("/v1/investigations/error", {"work_id": "w1", "error": "model unavailable"})


async def test_sessions_survive_a_restart(tmp_path: Path) -> None:
    first, _, _ = node(tmp_path, lambda r: StubTurn(text="ok"))
    first.accept(payload())
    await first.drain()
    second, _, engine = node(tmp_path, lambda r: StubTurn(text="ok"))
    second.accept(payload())
    await second.drain()
    assert engine.requests[0].session == "stub-1"


async def test_failed_posture_refuses_work(tmp_path: Path) -> None:
    checks = ({"name": "cannot delete pods", "argv": ["echo", "yes"], "expect": "^no"},)
    investigator, _, _ = node(tmp_path, lambda r: StubTurn(text="ok"), posture_checks=checks)
    await investigator.check_posture()
    assert not investigator.ready and investigator.accept(payload())[0] == 503
    assert (await investigator.answer({"work_id": "w1", "question": "?"}))[0] == 503


async def test_answering_a_consult_has_no_way_to_ask_a_third(tmp_path: Path) -> None:
    investigator, _, engine = node(tmp_path, lambda r: StubTurn(text="the pool is 10"))
    status, body = await investigator.answer({"work_id": "w1", "from": "code", "question": "pool size?", "context": {}})
    assert (status, body) == (200, {"answer": "the pool is 10"}) and engine.requests[0].consult is None


async def test_the_doors_need_the_profile_secret(tmp_path: Path) -> None:
    investigator, _, _ = node(tmp_path, lambda r: StubTurn(text="ok"))
    app = create_node_app(investigator)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://infra") as client:
        body = json.dumps(payload()).encode()
        assert (await client.post("/investigate", content=body)).status_code == 401
        body, headers = signed(SECRET, payload())
        assert (await client.post("/investigate", content=body, headers=headers)).status_code == 202
        await investigator.drain()
        assert (await client.get("/healthz")).json()["profile"] == "infra"


def test_node_configuration_comes_from_the_environment(tmp_path: Path) -> None:
    posture = tmp_path / "posture.yaml"
    posture.write_text("- name: x\n  argv: [echo, no]\n  expect: '^no'\n")
    config = load_node(
        {
            "AIRLOCK_PROFILE": "infra",
            "AIRLOCK_SECRET": "s",
            "AIRLOCK_CONTROL_URL": "http://control/",
            "AIRLOCK_POSTURE_FILE": str(posture),
            "AIRLOCK_MCP_ALLOWED": "mcp__grafana__query, mcp__jira__search",
        }
    )
    assert config.control_url == "http://control" and config.posture_checks[0]["name"] == "x"
    assert config.mcp_allowed == {"mcp__grafana__query", "mcp__jira__search"}
    with pytest.raises(SystemExit):
        load_node({})
