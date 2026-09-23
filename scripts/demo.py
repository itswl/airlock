"""Run the whole system on this machine, with no model and no Docker: python scripts/demo.py

Four servers on 127.0.0.1 in one process: the control plane (the web console),
two investigators on the stub engine (infra consults code), and the launcher on
the local runtime (plain processes, recorded as isolation: none). One demo alert
arrives through the signed intake; the investigator answers with a plan whose
steps are harmless `echo` commands. Open the console, read the plan, write a
message to get a revision ("先 drain"), approve it, and watch the record.

Everything it writes goes under data/demo/<timestamp>/ in this checkout.
Nothing is read from or written to anywhere else, and no credential is used.

    python scripts/demo.py            ports 18080 (console), 18090, 18101, 18102
    python scripts/demo.py --smoke    ephemeral ports; drives the whole flow itself and exits

With --engine claude the two investigators run the real Claude engine instead
of the stub, against whatever gateway ANTHROPIC_BASE_URL / ANTHROPIC_AUTH_TOKEN
name (model: AIRLOCK_MODEL). They run confined (airlock.runner.sandbox): their
working directories are fresh temp directories outside this checkout, seeded
with a made-up incident, and their tools cannot reach anything else.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import re
import secrets
import socket
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx
import uvicorn

from airlock.config import load_control, load_launcher
from airlock.control.app import create_app
from airlock.control.auth import hash_password
from airlock.control.service import ControlPlane
from airlock.crypto import sign
from airlock.launcher.app import create_launcher_app
from airlock.launcher.runtime import LocalRuntime
from airlock.launcher.service import Launcher
from airlock.runner.engine import Engine, EngineRequest, StubEngine, StubTurn
from airlock.runner.investigator import InvestigatorNode, NodeConfig, create_node_app

ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "airlock-demo-password"  # noqa: S105 — the demo console on 127.0.0.1, printed at start


def plan(summary: str, steps: list[dict[str, Any]]) -> str:
    body = {
        "summary": summary,
        "changes": "The demo api is restarted. Nothing real is touched: every step is an echo.",
        "risk": "low",
        "permissions": {"ops": ["svc:restart"]},
        "steps": steps,
        "rollback": "Nothing to roll back: a restart does not change configuration.",
        "verification": "The api health check answers 200 within a minute.",
        "evidence": "pool exhausted errors in every pod since 09:12; the database is healthy",
    }
    return "```plan\n" + json.dumps(body, indent=2, ensure_ascii=False) + "\n```"


def infra(request: EngineRequest) -> StubTurn:
    said = " ".join(m["text"] for m in request.context.get("messages") or [] if m["author"] == "operator")
    if "drain" in said:
        steps = [
            {
                "worker": "ops",
                "target": "demo/api",
                "argv": ["echo", "draining", "api"],
                "why": "you asked to drain first",
            },
            {"worker": "ops", "target": "demo/api", "argv": ["sleep", "2"], "why": "let in-flight requests finish"},
            {"worker": "ops", "target": "demo/api", "argv": ["echo", "restarting", "api"], "why": "new pods, new pool"},
        ]
        return StubTurn(text="按你说的，先 drain 再重启。\n\n" + plan("Drain, then restart the demo api", steps))
    steps = [
        {"worker": "ops", "target": "demo/api", "argv": ["echo", "restarting", "api"], "why": "new pods, new pool"},
        {"worker": "ops", "target": "demo/api", "argv": ["true"], "why": "stand-in for the health check"},
    ]
    return StubTurn(
        consults=[("code", "09:10 前后有没有发版？")],
        tools=[
            ("Bash", {"command": "kubectl -n demo get pods"}),
            ("Bash", {"command": "kubectl -n demo delete pod api-1"}),
        ],
        text=lambda t: (
            "连接池耗尽，数据库正常。"
            f"问了 code：{t.answers[0] if t.answers else '（没答上）'}\n"
            "（调查员试了一次删 pod，被只读守卫拦下，记录里能看到。）\n\n" + plan("Restart the demo api", steps)
        ),
    )


def code(request: EngineRequest) -> StubTurn:
    return StubTurn(text="有：09:10 那次发版把连接池从 20 改成了 10。")


EVIDENCE = {
    "infra": {
        "README.md": (
            "Demo environment. demo/api runs 3 pods behind the ops worker. There is no real cluster:\n"
            "everything you can look at is in this directory.\n"
        ),
        "logs/api.log": "".join(
            f"2026-09-23T09:{m:02d}:{s:02d}Z api-{p} ERROR pool exhausted: 10/10 connections in use, waited 5000ms\n"
            f"2026-09-23T09:{m:02d}:{s:02d}Z api-{p} WARN request failed status=503 path=/v1/checkout\n"
            for m, s, p in [(12, 3, 1), (12, 9, 2), (14, 40, 3), (19, 2, 1), (27, 55, 2), (33, 18, 3), (39, 47, 1)]
        )
        + "2026-09-23T09:05:11Z api-1 INFO pool ok: 6/20 connections in use\n",
        "metrics/summary.txt": (
            "window         5xx_rate  p99_ms  db_cpu  db_connections\n"
            "09:00-09:10    0.2%      180     21%     34/200\n"
            "09:12-09:40    7.1%      4200    22%     30/200\n"
        ),
        # The runbook is a skill: the investigator loads it when the logs say "pool exhausted".
        ".claude/skills/pool-exhaustion/SKILL.md": (
            "---\n"
            "name: pool-exhaustion\n"
            'description: How to investigate and fix connection-pool exhaustion on demo/api. Use when logs say "pool exhausted".\n'
            "---\n"
            "# Pool exhaustion on demo/api\n\n"
            "1. Compare the pool limit in the errors with the database's own connection usage.\n"
            "2. A recent change to the pool size is the usual cause: ask the code investigator for the deploy history.\n"
            "3. A restart alone recreates the same pool; the fix restores the limit.\n\n"
            "In this demo the ops worker simulates every action with echo, one line per action:\n"
            "  echo drain deployment/api\n"
            "  echo set max_connections=20 deployment/api\n"
            "  echo rollout restart deployment/api\n"
        ),
    },
    "code": {
        # The deploy history is not a file here: it comes from the demo MCP server.
        "config/pool.yaml": "max_connections: 10   # 20 before v2.14.0\nacquire_timeout_ms: 5000\n",
    },
}
INSTRUCTIONS = {
    "infra": (
        "Demo. You look at demo/api through the files in your working directory (logs, metrics) and your skills. "
        "You do NOT have the deploy history or the configuration; the code investigator does. Ask it with the "
        "consult tool when a change in code or configuration could explain what you see."
    ),
    "code": (
        "Demo. demo/api's configuration is in your working directory; its deploy history comes from the demo MCP "
        "server's deploy_history tool. Answer from those."
    ),
}


def seed(workdir: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        path = workdir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def bind(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    return sock


def build(ports: dict[str, int], data: Path) -> tuple[dict[str, Any], dict[str, str]]:
    env = {name: secrets.token_hex(16) for name in ("SESSION", "LAUNCHER", "ALERTS", "INFRA", "CODE")}
    env["PASSWORD_HASH"] = hash_password(PASSWORD)
    config = {
        "control": {
            "base_url": f"http://127.0.0.1:{ports['control']}",
            "db_path": str(data / "control.db"),
            "session_secret_env": "SESSION",
        },
        "operator": {"name": "operator", "password_hash_env": "PASSWORD_HASH"},
        "launcher": {
            "url": f"http://127.0.0.1:{ports['launcher']}",
            "secret_env": "LAUNCHER",
            "control_url": f"http://127.0.0.1:{ports['control']}",
            "db_path": str(data / "launcher.db"),
            "runs_dir": str(data / "runs"),
            "runtime": "local",
        },
        "sources": [
            {
                "name": "alerts",
                "verify": "hmac",
                "secret_env": "ALERTS",
                "accept": [{"when": {"status": "firing"}}],
                "map": {"title": "{alertname}: {summary}", "body": "{description}", "key": "{fingerprint}"},
            }
        ],
        "routes": [{"investigator": "infra"}],
        "investigators": [
            {
                "name": "infra",
                "url": f"http://127.0.0.1:{ports['infra']}",
                "secret_env": "INFRA",
                "may_consult": ["code"],
            },
            {"name": "code", "url": f"http://127.0.0.1:{ports['code']}", "secret_env": "CODE"},
        ],
        "workers": [
            {
                "name": "ops",
                "modes": ["commands"],
                "allowed_permissions": ["svc:restart"],
                "command_allowlist": [r"echo [a-z0-9 ./:=_-]+", "true", r"sleep [0-9]"],
            }
        ],
    }
    return config, env


async def send_alert(control_url: str, secret: str) -> str:
    body = json.dumps(
        {
            "status": "firing",
            "alertname": "HighErrorRate",
            "summary": "demo api 5xx over 5%",
            "description": "demo/api returns 5xx for 7% of requests since 09:12. Pool exhausted errors in the logs.",
            "fingerprint": secrets.token_hex(4),
        }
    ).encode()
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{control_url}/v1/intake/alerts", content=body, headers=sign(secret, body))
    response.raise_for_status()
    return str(response.json()["work_id"])


async def smoke(
    control_url: str, plane: ControlPlane, work_id: str, *, real: bool = False, scratch: Path | None = None
) -> None:
    """Do what a person would: wait for the plan, ask for a revision, approve it, wait for the record."""
    patience = 900.0 if real else 30.0

    async def state_is(*states: str, within: float = patience) -> str:
        deadline = time.monotonic() + within
        while time.monotonic() < deadline:
            state = str((plane.work(work_id) or {}).get("state"))
            if state in states:
                return state
            await asyncio.sleep(0.2)
        raise SystemExit(f"smoke: {work_id} stuck in {(plane.work(work_id) or {}).get('state')}")

    started = time.monotonic()
    async with httpx.AsyncClient(base_url=control_url, follow_redirects=False) as web:
        first = await state_is("plan_ready", "answered", "plan_invalid", "error")
        print(f"smoke: first round ended {first} after {time.monotonic() - started:.0f}s")
        if first != "plan_ready":
            report(plane, work_id)
            raise SystemExit(1)
        assert (await web.post("/login", data={"password": PASSWORD})).status_code == 303
        page = (await web.get(f"/work/{work_id}")).text
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)  # type: ignore[union-attr]
        await web.post(f"/work/{work_id}/message", data={"text": "先 drain 再重启", "csrf": csrf})
        await state_is("queued", "investigating", within=10)
        second = await state_is("plan_ready", "answered", "plan_invalid", "error")
        print(f"smoke: revision round ended {second} after {time.monotonic() - started:.0f}s")
        if second != "plan_ready":
            report(plane, work_id)
            raise SystemExit(1)
        page = (await web.get(f"/work/{work_id}")).text
        version = re.search(r'name="version" value="([0-9]+)"', page).group(1)  # type: ignore[union-attr]
        digest = re.search(r'name="plan_hash" value="([0-9a-f]+)"', page).group(1)  # type: ignore[union-attr]
        await web.post(f"/work/{work_id}/approve", data={"version": version, "plan_hash": digest, "csrf": csrf})
        final = await state_is("done", "failed", "refused", within=120)
    detail = plane.detail(work_id) or {}
    steps = [s["detail"] for s in detail.get("steps", []) if s["event"] == "step.end"]
    print(f"smoke: {final}, plan v{version}, steps {steps}, ledger intact: {plane.ledger.verify()['intact']}")
    if real:
        report(plane, work_id)
        if scratch is not None:
            tool_use(scratch)
    if final != "done" or (not real and len(steps) != 3):
        raise SystemExit(1)


def report(plane: ControlPlane, work_id: str) -> None:
    """What the investigators said and did, for reading after a real run."""
    detail = plane.detail(work_id) or {}
    for message in detail.get("messages", []):
        print(f"\n--- {message['author']} ({message['via']})\n{message['text'][:1500]}")
    for consult in detail.get("consults", []):
        print(f"\n--- consult {consult['from_profile']} -> {consult['to_profile']} ({consult['status']})")
        print(f"Q: {consult['question'][:500]}\nA: {(consult['answer'] or '')[:800]}")
    for plan in reversed(detail.get("plans", [])):
        steps = [" ".join(s.get("argv") or [s.get("task") or ""]) for s in plan["plan"]["steps"]]
        print(f"\n--- plan v{plan['version']} risk={plan['plan']['risk']} errors={plan['errors']}\n    steps: {steps}")
    for entry in detail.get("ledger", []):
        data = entry["data"]
        keep = {
            k: data[k]
            for k in ("cost_usd", "turns", "refusals", "usage", "version", "status", "errors", "reason")
            if k in data
        }
        print(
            f"ledger {entry['seq']:>3} {entry['kind']:<28} {entry['actor']:<22} {json.dumps(keep, ensure_ascii=False)[:200]}"
        )


def tool_use(scratch: Path) -> None:
    """Which tools each investigator called or was refused, from its own record."""
    for name in ("infra", "code"):
        seen: dict[str, int] = {}
        for record in sorted((scratch / f"{name}.state" / "records").glob("*.jsonl")):
            for raw in record.read_text(encoding="utf-8").splitlines():
                line = json.loads(raw)
                if line["kind"] in ("tool.call", "tool.refused"):
                    label = f"{line['data'].get('tool')}{' (refused)' if line['kind'] == 'tool.refused' else ''}"
                    seen[label] = seen.get(label, 0) + 1
        print(f"tools {name}: " + ", ".join(f"{k} x{v}" for k, v in sorted(seen.items())))


def engine_for(name: str, kind: str, mcp_config: Path | None = None) -> Engine:
    if kind == "stub":
        return StubEngine(infra if name == "infra" else code)
    from airlock.runner.claude_engine import ClaudeEngine
    from airlock.runner.sandbox import CONFINED_TOOLS

    budget = float(os.environ.get("AIRLOCK_MAX_BUDGET_USD") or 1.0)
    return ClaudeEngine(
        model=os.environ.get("AIRLOCK_MODEL") or None,
        tools=CONFINED_TOOLS,
        max_budget_usd=budget,
        mcp_config=mcp_config,
        skills="all" if name == "infra" else None,
    )


def mcp_config_for(scratch: Path) -> Path:
    """The code investigator's MCP servers: the demo one. Outside its working directory, as a real one must be."""
    path = scratch / "code.mcp.json"
    server = {"command": sys.executable, "args": [str(ROOT / "scripts" / "demo_mcp.py")]}
    path.write_text(json.dumps({"mcpServers": {"demo": server}}), encoding="utf-8")
    return path


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--smoke", action="store_true", help="drive the flow on ephemeral ports, then exit")
    parser.add_argument("--engine", choices=("stub", "claude"), default="stub")
    args = parser.parse_args()
    real = args.engine == "claude"

    defaults = {"control": 18080, "launcher": 18090, "infra": 18101, "code": 18102}
    sockets = {name: bind(0 if args.smoke else port) for name, port in defaults.items()}
    ports = {name: sock.getsockname()[1] for name, sock in sockets.items()}
    data = ROOT / "data" / "demo" / time.strftime("%Y%m%d-%H%M%S")
    data.mkdir(parents=True)
    config, env = build(ports, data)

    plane = ControlPlane(load_control(config, env))
    apps = {"control": create_app(plane.config, plane=plane, tick_seconds=0.5)}
    # A real engine gets working directories outside this checkout: nothing of
    # the repository (its git metadata included) is in reach or in its prompt.
    scratch = Path(tempfile.mkdtemp(prefix="airlock-demo-")) if real else data
    for name in ("infra", "code"):
        workdir = scratch / name
        mcp_config = None
        if real:
            seed(workdir, EVIDENCE[name])
            mcp_config = mcp_config_for(scratch) if name == "code" else None
        settings = NodeConfig(
            profile=name,
            secret=env[name.upper()],
            control_url=config["control"]["base_url"],
            engine=args.engine,
            workdir=workdir,
            instructions=INSTRUCTIONS[name] if real else "",
            confine=real,
            max_turns=25,
            timeout_seconds=600,
            mcp_allowed=frozenset({"mcp__demo__deploy_history"}) if mcp_config else frozenset(),
            state_dir=scratch / f"{name}.state" if real else None,
        )
        apps[name] = create_node_app(InvestigatorNode(settings, engine_for(name, args.engine, mcp_config)))
    launcher = Launcher(load_launcher(config, env), LocalRuntime(), engine="stub")
    apps["launcher"] = create_launcher_app(launcher, tick_seconds=2)

    servers = {name: uvicorn.Server(uvicorn.Config(apps[name], log_level="warning")) for name in apps}
    tasks = [asyncio.create_task(servers[name].serve(sockets=[sockets[name]])) for name in apps]
    while not all(s.started for s in servers.values()):
        await asyncio.sleep(0.05)

    control_url = config["control"]["base_url"]
    work_id = await send_alert(control_url, env["ALERTS"])
    if real:
        print(f"investigators work in {scratch}")
    if args.smoke:
        try:
            await smoke(control_url, plane, work_id, real=real, scratch=scratch if real else None)
        finally:
            for server in servers.values():
                server.should_exit = True
            await asyncio.gather(*tasks, return_exceptions=True)
        return 0

    print(
        f"\n  console   {control_url}/work/{work_id}\n  password  {PASSWORD}\n  data      {data}\n\n  Ctrl+C to stop.\n"
    )
    await asyncio.gather(*tasks)
    return 0


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        sys.exit(asyncio.run(main()))
