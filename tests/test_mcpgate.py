"""The MCP gateway: it holds the credential, forwards the named reads, and nothing else reaches the server."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from airlock.mcpgate import GateConfigError, create_gate_app, load_gate
from airlock.runner.gate import mcp_deny_reason
from airlock.runner.recorder import Recorder, read_lines, verify_lines

TOOLS = ["get_alert", "list_alerts", "search_knowledge_base", "propose_remediation", "test_alert_payload"]
CONFIG = {
    "servers": {
        "alerts": {
            "url": "http://alerts.invalid/mcp/",
            "headers": {"Authorization": "Bearer ${ALERTS_KEY}"},
            "tools": ["get_*", "list_*", "search_knowledge_base"],
        },
        "other": {"url": "http://other.invalid/mcp/", "tools": ["*"]},
    },
    "clients": {
        "infra": {"token_env": "INFRA_TOKEN", "servers": ["alerts"]},
        "code": {"token_env": "CODE_TOKEN", "servers": ["other"]},
    },
}
ENV = {"ALERTS_KEY": "upstream-secret", "INFRA_TOKEN": "i" * 32, "CODE_TOKEN": "c" * 32}
INFRA = {"Authorization": "Bearer " + "i" * 32}


def upstream(seen: list[dict[str, Any]], *, events: bool = False) -> FastAPI:
    """Just enough of a Streamable-HTTP MCP server to answer, and to show what reached it."""
    app = FastAPI()

    @app.post("/mcp/")
    async def mcp(request: Request) -> Response:
        message = json.loads(await request.body())
        seen.append({"headers": dict(request.headers), "message": message})
        if message.get("method", "").startswith("notifications/"):
            return Response(status_code=202)
        if message["method"] == "tools/list":
            result: dict[str, Any] = {"tools": [{"name": n, "inputSchema": {"type": "object"}} for n in TOOLS]}
        elif message["method"] == "tools/call":
            result = {"content": [{"type": "text", "text": f"ran {message['params']['name']}"}]}
        else:
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}
        answer = {"jsonrpc": "2.0", "id": message["id"], "result": result}
        if events:
            body = f"event: message\ndata: {json.dumps(answer)}\n\n"
            return Response(body, media_type="text/event-stream", headers={"mcp-session-id": "s-1"})
        return JSONResponse(answer, headers={"mcp-session-id": "s-1"})

    return app


def gate(tmp_path: Path, seen: list[dict[str, Any]], **kwargs: Any) -> tuple[httpx.AsyncClient, Path]:
    config = tmp_path / "gate.json"
    config.write_text(json.dumps(CONFIG))
    servers, clients = load_gate(config, ENV)
    record = tmp_path / "calls.jsonl"
    app = create_gate_app(
        servers, clients, record=Recorder(record), transport=httpx.ASGITransport(app=upstream(seen, **kwargs))
    )
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gate"), record


def rpc(method: str, request_id: int = 1, **params: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


@pytest.mark.anyio
async def test_it_lists_and_forwards_only_the_named_reads_with_its_own_credential(tmp_path: Path) -> None:
    seen: list[dict[str, Any]] = []
    web, record = gate(tmp_path, seen)
    async with web:
        listed = (await web.post("/alerts/", json=rpc("tools/list"), headers=INFRA)).json()
        assert [t["name"] for t in listed["result"]["tools"]] == ["get_alert", "list_alerts", "search_knowledge_base"]
        called = await web.post(
            "/alerts/", json=rpc("tools/call", 2, name="get_alert", arguments={"id": 7}), headers=INFRA
        )
        assert called.json()["result"]["content"][0]["text"] == "ran get_alert"
        assert called.headers["mcp-session-id"] == "s-1"
    assert [s["headers"]["authorization"] for s in seen] == ["Bearer upstream-secret"] * 2  # never the client's token
    lines = read_lines(record)
    assert [(line["kind"], line["data"]["tool"]) for line in lines] == [("call.forwarded", "get_alert")]
    assert lines[0]["data"]["client"] == "infra" and lines[0]["data"]["status"] == 200
    assert verify_lines(lines)["intact"]


@pytest.mark.anyio
async def test_a_tool_that_is_not_named_never_reaches_the_server(tmp_path: Path) -> None:
    seen: list[dict[str, Any]] = []
    web, record = gate(tmp_path, seen)
    async with web:
        refused = await web.post(
            "/alerts/", json=rpc("tools/call", 3, name="propose_remediation", arguments={}), headers=INFRA
        )
        other = await web.post("/alerts/", json=rpc("resources/subscribe", 4, uri="x://y"), headers=INFRA)
        batch = await web.post(
            "/alerts/",
            json=[rpc("tools/call", 5, name="get_alert"), rpc("tools/call", 6, name="test_alert_payload")],
            headers=INFRA,
        )
    assert refused.status_code == 200 and refused.json()["error"]["code"] == -32602
    assert "propose_remediation" in refused.json()["error"]["message"]
    assert other.json()["error"]["code"] == -32601
    assert [a["id"] for a in batch.json()] == [5, 6] and all("error" in a for a in batch.json())
    assert seen == []
    assert [line["data"]["tool"] for line in read_lines(record)] == ["propose_remediation", "test_alert_payload"]


@pytest.mark.anyio
async def test_the_client_token_decides_which_servers_it_reaches(tmp_path: Path) -> None:
    seen: list[dict[str, Any]] = []
    web, _ = gate(tmp_path, seen)
    async with web:
        assert (await web.post("/alerts/", json=rpc("ping"))).status_code == 401
        wrong = {"Authorization": "Bearer " + "x" * 32}
        assert (await web.post("/alerts/", json=rpc("ping"), headers=wrong)).status_code == 401
        code = {"Authorization": "Bearer " + "c" * 32}
        assert (await web.post("/alerts/", json=rpc("ping"), headers=code)).status_code == 404
        assert (await web.post("/nowhere/", json=rpc("ping"), headers=INFRA)).status_code == 404
        assert (await web.post("/alerts", json=rpc("initialize"), headers=INFRA)).status_code == 200
        notified = await web.post(
            "/alerts/", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=INFRA
        )
        assert notified.status_code == 202
    assert [s["message"]["method"] for s in seen] == ["initialize", "notifications/initialized"]


@pytest.mark.anyio
async def test_an_event_stream_answer_is_filtered_too(tmp_path: Path) -> None:
    seen: list[dict[str, Any]] = []
    web, _ = gate(tmp_path, seen, events=True)
    async with web:
        listed = await web.post("/alerts/", json=rpc("tools/list", 9), headers=INFRA)
    assert listed.headers["content-type"].startswith("text/event-stream")
    data = [line[6:] for line in listed.text.splitlines() if line.startswith("data: ")]
    assert [t["name"] for t in json.loads(data[0])["result"]["tools"]] == [
        "get_alert",
        "list_alerts",
        "search_knowledge_base",
    ]
    assert "event: message" in listed.text


@pytest.mark.anyio
async def test_a_server_that_cannot_be_reached_is_a_502_and_the_call_is_recorded(tmp_path: Path) -> None:
    config = tmp_path / "gate.json"
    config.write_text(json.dumps(CONFIG))
    servers, clients = load_gate(config, ENV)

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    record = tmp_path / "calls.jsonl"
    app = create_gate_app(servers, clients, record=Recorder(record), transport=httpx.MockTransport(refuse))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gate") as web:
        answer = await web.post("/alerts/", json=rpc("tools/call", 1, name="list_alerts"), headers=INFRA)
    assert answer.status_code == 502
    assert [(line["kind"], line["data"]["reason"]) for line in read_lines(record)] == [("call.failed", "ConnectError")]


@pytest.mark.parametrize(
    ("change", "env", "message"),
    [
        ({}, {"INFRA_TOKEN": "i" * 32, "CODE_TOKEN": "c" * 32}, "${ALERTS_KEY} is not set"),
        ({}, {**ENV, "INFRA_TOKEN": "short"}, "shorter than 16"),
        ({}, {**ENV, "CODE_TOKEN": "i" * 32}, "shares its token"),
        ({"clients": {"infra": {"token_env": "INFRA_TOKEN", "servers": ["nope"]}}}, ENV, "no server named nope"),
        ({"clients": {}}, ENV, "no clients"),
        ({"servers": {"healthz": {"url": "http://x.invalid/", "tools": ["*"]}}}, ENV, "letters, digits"),
        ({"servers": {"alerts": {"url": "http://x.invalid/", "tools": []}}}, ENV, "tools must list"),
        ({"servers": {"alerts": {"url": "file:///etc/passwd", "tools": ["*"]}}}, ENV, "url must be http(s)"),
    ],
)
def test_a_configuration_that_cannot_be_used_says_why(
    tmp_path: Path, change: dict[str, Any], env: dict[str, str], message: str
) -> None:
    config = tmp_path / "gate.json"
    config.write_text(json.dumps({**CONFIG, **change}))
    with pytest.raises(GateConfigError, match=re.escape(message)):
        load_gate(config, env)


def test_the_investigator_allowlist_takes_patterns_inside_one_server() -> None:
    allowed = frozenset({"mcp__alerts__get_*", "mcp__alerts__search_knowledge_base", "mcp__grafana__*"})
    assert mcp_deny_reason("mcp__alerts__get_alert", allowed) is None
    assert mcp_deny_reason("mcp__alerts__search_knowledge_base", allowed) is None
    assert mcp_deny_reason("mcp__grafana__query", allowed) is None
    assert mcp_deny_reason("mcp__alerts__propose_remediation", allowed) is not None
    assert mcp_deny_reason("mcp__other__get_alert", allowed) is not None  # a pattern never crosses servers
