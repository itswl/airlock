"""The MCP gateway end to end: a real MCP server behind it, the raw protocol and the real CLI in front of it.

    python scripts/mcpgate_check.py                  # the raw protocol only
    python scripts/mcpgate_check.py --engine claude  # and the Claude Code CLI

1. scripts/demo_mcp.py serves Streamable HTTP in the SDK's default mode (sessions,
   event streams). It answers only its own credential and writes down every tool it runs.
2. airlock.mcpgate sits in front of it, holds that credential, and forwards
   deploy_history only.
3. A raw client — an agent with curl would be one — sends the gateway token. It is
   shown one tool, its restart_service call is refused, and a wrong token gets a 401.
4. With --engine claude, the real CLI runs through ClaudeEngine. The profile's own
   allowlist admits every demo tool, so the gateway is the only thing in the way.
   The CLI is told to use every tool it has. It sees one tool and calls it, and the
   server's log shows restart_service never ran.

The model settings come from the environment (ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN,
AIRLOCK_MODEL), as for demo.py. Exit code 1 when a check fails.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
ACCEPT = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_for(url: str, seconds: float = 20.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            httpx.get(url, timeout=1.0)
            return
        except httpx.HTTPError:
            time.sleep(0.2)
    raise SystemExit(f"{url} did not come up")


def answer(response: httpx.Response) -> dict[str, Any]:
    """The JSON-RPC message in a JSON answer or an event stream."""
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        data = [line[6:] for line in response.text.splitlines() if line.startswith("data: ")]
        return json.loads(data[-1])
    return response.json()


async def raw(url: str, token: str) -> dict[str, Any]:
    headers = {**ACCEPT, "Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=30) as web:
        init = await web.post(
            url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "check", "version": "0"},
                },
            },
            headers=headers,
        )
        session = {**headers, "mcp-session-id": init.headers.get("mcp-session-id", "")}
        await web.post(url, json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=session)
        listed = answer(await web.post(url, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=session))
        called = answer(
            await web.post(
                url,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "deploy_history", "arguments": {"service": "checkout"}},
                },
                headers=session,
            )
        )
        refused = answer(
            await web.post(
                url,
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "restart_service", "arguments": {"service": "checkout"}},
                },
                headers=session,
            )
        )
        wrong = await web.post(
            url,
            json={"jsonrpc": "2.0", "id": 5, "method": "ping"},
            headers={**ACCEPT, "Authorization": "Bearer " + "x" * 32},
        )
    return {
        "session_kept": bool(init.headers.get("mcp-session-id")),
        "tools_listed": [t["name"] for t in listed["result"]["tools"]],
        "allowed_call_answered": "v2.14.0" in json.dumps(called.get("result")),
        "refused_call_error": (refused.get("error") or {}).get("message"),
        "wrong_token_status": wrong.status_code,
    }


async def claude(url: str, token: str, scratch: Path) -> dict[str, Any]:
    from airlock.runner.claude_engine import ClaudeEngine
    from airlock.runner.engine import EngineRequest, ToolPolicy
    from airlock.runner.guard import READONLY
    from airlock.runner.sandbox import CONFINED_TOOLS

    config = scratch / "mcp.json"
    config.write_text(
        json.dumps(
            {"mcpServers": {"demo": {"type": "http", "url": url, "headers": {"Authorization": f"Bearer {token}"}}}}
        )
    )
    workdir = scratch / "work"
    workdir.mkdir()
    lines: list[tuple[str, dict[str, Any]]] = []
    policy = ToolPolicy(
        READONLY,
        workdir,
        mcp_allowed=frozenset({"mcp__demo__*"}),  # the profile admits everything: the gateway is what is being tested
        record=lambda kind, **data: lines.append((kind, data)),
        confine=True,
    )
    engine = ClaudeEngine(
        model=os.environ.get("AIRLOCK_MODEL") or None, tools=CONFINED_TOOLS, max_budget_usd=0.5, mcp_config=config
    )
    request = EngineRequest(
        prompt=(
            "Use the MCP server named demo. First say exactly which demo tools you have. Then call its deploy history "
            "tool for the service 'checkout'. If you have any tool that restarts a service, restart 'checkout' with it. "
            "Finish with one line: TOOLS=<comma-separated demo tool names you had>."
        ),
        system="You are checking a tool setup. Be brief.",
        mode=READONLY,
        workdir=workdir,
        max_turns=8,
        timeout_seconds=300,
    )
    result = await engine.run(request, policy)
    return {
        "error": result.error,
        "tool_calls": [d.get("tool") for kind, d in lines if kind == "tool.call"],
        "refused_by_profile": [d.get("tool") for kind, d in lines if kind == "tool.refused"],
        "said": result.text.strip().splitlines()[-1][:200] if result.text.strip() else "",
        "cost_usd": result.cost_usd,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--engine", choices=("none", "claude"), default="none")
    args = parser.parse_args()
    upstream_credential, gate_token = secrets.token_hex(16), secrets.token_hex(16)
    with tempfile.TemporaryDirectory(prefix="mcpgate-") as tmp:
        scratch = Path(tmp)
        server_port, gate_port = free_port(), free_port()
        log = scratch / "server.log"
        log.touch()
        gate_config = scratch / "gate.json"
        gate_config.write_text(
            json.dumps(
                {
                    "servers": {
                        "demo": {
                            "url": f"http://127.0.0.1:{server_port}/mcp",
                            "headers": {"Authorization": "Bearer ${DEMO_CREDENTIAL}"},
                            "tools": ["deploy_history"],
                        }
                    },
                    "clients": {"check": {"token_env": "GATE_TOKEN", "servers": ["demo"]}},
                }
            )
        )
        base = {k: v for k, v in os.environ.items() if not k.startswith(("DEMO_", "GATE_"))}
        server = subprocess.Popen(
            [sys.executable, str(ROOT / "scripts" / "demo_mcp.py"), "--http", str(server_port)],
            env={**base, "DEMO_MCP_TOKEN": upstream_credential, "DEMO_MCP_LOG": str(log)},
        )
        gate = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "airlock.mcpgate",
                "--config",
                str(gate_config),
                "--port",
                str(gate_port),
                "--record",
                str(scratch / "calls.jsonl"),
            ],
            env={**base, "DEMO_CREDENTIAL": upstream_credential, "GATE_TOKEN": gate_token},
            cwd=ROOT,
        )
        try:
            wait_for(f"http://127.0.0.1:{server_port}/mcp")
            wait_for(f"http://127.0.0.1:{gate_port}/healthz")
            url = f"http://127.0.0.1:{gate_port}/demo/"
            direct = httpx.post(
                f"http://127.0.0.1:{server_port}/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={**ACCEPT, "Authorization": f"Bearer {gate_token}"},
            )
            report: dict[str, Any] = {
                "server_refuses_the_gate_token": direct.status_code == 401,
                "raw": asyncio.run(raw(url, gate_token)),
            }
            if args.engine == "claude":
                report["claude"] = asyncio.run(claude(url, gate_token, scratch))
            report["server_ran"] = log.read_text().splitlines()
            report["gateway_record"] = [
                (line["kind"], line["data"]["client"], line["data"]["tool"])
                for line in map(json.loads, (scratch / "calls.jsonl").read_text().splitlines())
            ]
        finally:
            for process in (gate, server):
                process.terminate()
                process.wait(timeout=10)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    raw_ok = report["raw"]
    ok = (
        report["server_refuses_the_gate_token"]
        and raw_ok["tools_listed"] == ["deploy_history"]
        and raw_ok["allowed_call_answered"]
        and bool(raw_ok["refused_call_error"])
        and raw_ok["wrong_token_status"] == 401
        and not any(line.startswith("restart_service") for line in report["server_ran"])
    )
    if "claude" in report:
        ok = ok and "mcp__demo__deploy_history" in report["claude"]["tool_calls"] and not report["claude"]["error"]
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
