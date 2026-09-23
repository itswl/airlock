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
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import re
import secrets
import socket
import sys
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
from airlock.runner.engine import EngineRequest, StubEngine, StubTurn
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
                "command_allowlist": [r"echo [a-z0-9 .:-]+", "true", r"sleep [0-9]"],
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


async def smoke(control_url: str, plane: ControlPlane, work_id: str) -> None:
    """Do what a person would: wait for the plan, ask for a revision, approve it, wait for the record."""

    async def state_is(*states: str, within: float = 30) -> str:
        deadline = time.monotonic() + within
        while time.monotonic() < deadline:
            state = str((plane.work(work_id) or {}).get("state"))
            if state in states:
                return state
            await asyncio.sleep(0.2)
        raise SystemExit(f"smoke: {work_id} stuck in {(plane.work(work_id) or {}).get('state')}")

    async with httpx.AsyncClient(base_url=control_url, follow_redirects=False) as web:
        await state_is("plan_ready")
        assert (await web.post("/login", data={"password": PASSWORD})).status_code == 303
        page = (await web.get(f"/work/{work_id}")).text
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)  # type: ignore[union-attr]
        await web.post(f"/work/{work_id}/message", data={"text": "先 drain 再重启", "csrf": csrf})
        await state_is("queued", "investigating", within=5)
        await state_is("plan_ready")
        page = (await web.get(f"/work/{work_id}")).text
        version = re.search(r'name="version" value="([0-9]+)"', page).group(1)  # type: ignore[union-attr]
        digest = re.search(r'name="plan_hash" value="([0-9a-f]+)"', page).group(1)  # type: ignore[union-attr]
        await web.post(f"/work/{work_id}/approve", data={"version": version, "plan_hash": digest, "csrf": csrf})
        final = await state_is("done", "failed", "refused")
    detail = plane.detail(work_id) or {}
    steps = [s["detail"] for s in detail.get("steps", []) if s["event"] == "step.end"]
    print(f"smoke: {final}, plan v{version}, steps {steps}, ledger intact: {plane.ledger.verify()['intact']}")
    if final != "done" or len(steps) != 3:
        raise SystemExit(1)


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--smoke", action="store_true", help="drive the flow on ephemeral ports, then exit")
    args = parser.parse_args()

    defaults = {"control": 18080, "launcher": 18090, "infra": 18101, "code": 18102}
    sockets = {name: bind(0 if args.smoke else port) for name, port in defaults.items()}
    ports = {name: sock.getsockname()[1] for name, sock in sockets.items()}
    data = ROOT / "data" / "demo" / time.strftime("%Y%m%d-%H%M%S")
    data.mkdir(parents=True)
    config, env = build(ports, data)

    plane = ControlPlane(load_control(config, env))
    apps = {"control": create_app(plane.config, plane=plane, tick_seconds=0.5)}
    for name, script in (("infra", infra), ("code", code)):
        settings = NodeConfig(
            profile=name,
            secret=env[name.upper()],
            control_url=config["control"]["base_url"],
            engine="stub",
            workdir=data / name,
        )
        apps[name] = create_node_app(InvestigatorNode(settings, StubEngine(script)))
    launcher = Launcher(load_launcher(config, env), LocalRuntime(), engine="stub")
    apps["launcher"] = create_launcher_app(launcher, tick_seconds=2)

    servers = {name: uvicorn.Server(uvicorn.Config(apps[name], log_level="warning")) for name in apps}
    tasks = [asyncio.create_task(servers[name].serve(sockets=[sockets[name]])) for name in apps]
    while not all(s.started for s in servers.values()):
        await asyncio.sleep(0.05)

    control_url = config["control"]["base_url"]
    work_id = await send_alert(control_url, env["ALERTS"])
    if args.smoke:
        try:
            await smoke(control_url, plane, work_id)
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
