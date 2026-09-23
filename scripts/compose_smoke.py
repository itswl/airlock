"""Run deploy/compose.yml as written, push one signal through it, and take it down again.

    python scripts/compose_smoke.py

What it proves, on this machine's Docker:

* the images build (deploy/Dockerfile and deploy/Dockerfile.launcher);
* the compose file starts: control plane, launcher with the Docker socket,
  two investigators, the egress proxy and the MCP gateway, on the five networks;
* a signed signal reaches an investigator in its container, its plan comes back,
  an approval through the console launches a worker container from inside the
  launcher container, and the run's record says isolation: container;
* the network split holds from inside an investigator: the launcher does not
  even resolve, the internet is unreachable directly, the proxy passes a listed
  host and refuses an unlisted one; the MCP gateway answers the infra
  investigator and does not resolve for the code one.

Engines are stubs (no model, no key) and the worker only runs echo. Everything
lives under data/compose-<time>/ in this checkout and under a compose project
named airlock-smoke-<random>; both are removed at the end, pass or fail.

    python scripts/compose_smoke.py --engine claude

runs the infra investigator on the real Claude engine instead, inside its
container: ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN and AIRLOCK_MODEL come
from the environment, the gateway becomes the proxy's only listed host, and
the run also checks that the model's calls went out through the proxy. The
container sees a made-up incident and nothing else of this machine.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from airlock.control.auth import hash_password
from airlock.crypto import sign

ROOT = Path(__file__).resolve().parent.parent
PASSWORD = "compose-smoke-password"  # noqa: S105 — a throwaway console on 127.0.0.1, deleted at the end

REPLY = """Findings: demo/api has exhausted its connection pool since 09:12; the database is healthy.

```plan
{
  "summary": "Restart demo/api",
  "changes": "demo/api is restarted; nothing else changes.",
  "risk": "low",
  "permissions": {"ops": ["svc:restart"]},
  "steps": [
    {"worker": "ops", "target": "demo/api", "argv": ["echo", "rollout", "restart", "deployment/api"], "why": "new pool"},
    {"worker": "ops", "target": "demo/api", "argv": ["true"], "why": "stand-in for the health check"}
  ],
  "rollback": "Nothing to roll back.",
  "verification": "The health check answers 200."
}
```
"""

NETWORK_PROBE = """
import socket
def reach(host, port):
    try:
        socket.create_connection((host, port), 3)
        return "reachable"
    except socket.gaierror:
        return "does not resolve"
    except OSError:
        return "unreachable"
def proxy(target):
    s = socket.create_connection(("egress", 8888), 5)
    s.sendall(f"CONNECT {target} HTTP/1.1\\r\\nHost: {target}\\r\\n\\r\\n".encode())
    return s.recv(200).decode(errors="replace").split("\\r\\n")[0]
import sys
import urllib.request
def health(url):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        return opener.open(url, timeout=5).status
    except OSError as exc:
        return type(exc).__name__
print("launcher:", reach("launcher", 8090))
print("internet:", reach("1.1.1.1", 443))
print("listed:", proxy(sys.argv[1] + ":443"))
print("unlisted:", proxy("example.com:443"))
print("mcp gate:", reach("mcp-gate", 8097))
print("mcp gate health:", health("http://mcp-gate:8097/healthz"))
"""
EVIDENCE = {
    "README.md": "Demo environment. demo/api runs 3 pods behind the ops worker. Everything you can look at is here.\n",
    "logs/api.log": "".join(
        f"2026-09-23T09:{m:02d}:00Z api-{p} ERROR pool exhausted: 10/10 connections in use, waited 5000ms\n"
        for m, p in [(12, 1), (14, 3), (19, 1), (27, 2), (39, 1)]
    ),
    "metrics/summary.txt": "window 09:00-09:10 5xx 0.2% db_connections 34/200\nwindow 09:12-09:40 5xx 7.1% db_connections 30/200\n",
}
SKILL = """---
name: pool-exhaustion
description: How to handle connection-pool exhaustion on demo/api. Use when logs say "pool exhausted".
---
Compare the pool limit in the errors with the database's own usage; a restart recreates the same pool.
In this demo the ops worker simulates every action with one echo line, for example:
  echo drain deployment/api
  echo set max_connections=20 deployment/api
  echo rollout restart deployment/api
"""
REAL_INSTRUCTIONS = (
    "Demo. You look at demo/api through the files in your working directory (logs, metrics) and your skills. "
    "Nothing else of this machine is visible to you, and nothing needs to be."
)


def run(*argv: str, env: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    done = subprocess.run(list(argv), capture_output=True, text=True, check=False, env=env)
    if check and done.returncode != 0:
        raise SystemExit(f"compose smoke: {' '.join(argv[:4])} failed:\n{(done.stderr or done.stdout)[-1500:]}")
    return done


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def lay_out(root: Path, port: int, real: dict[str, str] | None = None) -> dict[str, str]:
    """Every file and directory the compose file refers to, with fresh secrets."""
    names = ("SESSION", "LAUNCHER", "ALERTS", "INFRA", "CODE")
    secret = {name: secrets.token_hex(24) for name in names}
    for sub in (
        "data",
        "runs",
        "work/infra",
        "work/code",
        "state/infra",
        "state/code",
        "creds/investigator-infra",
        "code",
        "profiles/skills-infra",
        "data/mcp-gate",
    ):
        (root / sub).mkdir(parents=True, exist_ok=True)
        (root / sub).chmod(0o777)  # the containers run as uid 10001
    config = {
        "control": {
            "base_url": f"http://127.0.0.1:{port}",
            "db_path": str(root / "data" / "control.db"),
            "session_secret_env": "AIRLOCK_SESSION_SECRET",
        },
        "operator": {"name": "operator", "password_hash_env": "AIRLOCK_OPERATOR_PASSWORD_HASH"},
        "launcher": {
            "url": "http://launcher:8090",
            "secret_env": "AIRLOCK_LAUNCHER_SECRET",
            "control_url": "http://control:8080",
            "db_path": str(root / "data" / "launcher.db"),
            "runs_dir": str(root / "runs"),
            "runtime": "docker",
        },
        "sources": [
            {
                "name": "alerts",
                "verify": "hmac",
                "secret_env": "AIRLOCK_ALERTS_SECRET",
                "accept": [{"when": {"status": "firing"}}],
                "map": {"title": "{alertname}", "body": "{description}", "key": "{fingerprint}"},
            }
        ],
        "routes": [{"investigator": "infra"}],
        "investigators": [
            {
                "name": "infra",
                "url": "http://investigator-infra:8100",
                "secret_env": "AIRLOCK_INVESTIGATOR_INFRA_SECRET",
            },
            {"name": "code", "url": "http://investigator-code:8100", "secret_env": "AIRLOCK_INVESTIGATOR_CODE_SECRET"},
        ],
        "workers": [
            {
                "name": "ops",
                "modes": ["commands"],
                "image": "airlock:dev",
                "allowed_permissions": ["svc:restart"],
                "command_allowlist": [r"echo [a-z0-9 ./:=_-]+", "true"],
            }
        ],
    }
    (root / "config.yaml").write_text(json.dumps(config, indent=2))  # JSON is YAML
    (root / "control.env").write_text(
        f"AIRLOCK_SESSION_SECRET={secret['SESSION']}\n"
        f"AIRLOCK_OPERATOR_PASSWORD_HASH='{hash_password(PASSWORD)}'\n"
        f"AIRLOCK_LAUNCHER_SECRET={secret['LAUNCHER']}\n"
        f"AIRLOCK_ALERTS_SECRET={secret['ALERTS']}\n"
        f"AIRLOCK_INVESTIGATOR_INFRA_SECRET={secret['INFRA']}\n"
        f"AIRLOCK_INVESTIGATOR_CODE_SECRET={secret['CODE']}\n"
    )
    (root / "launcher.env").write_text(f"AIRLOCK_LAUNCHER_SECRET={secret['LAUNCHER']}\n")
    if real is None:
        (root / "investigator-infra.env").write_text(
            f"AIRLOCK_SECRET={secret['INFRA']}\nAIRLOCK_ENGINE=stub\nAIRLOCK_STUB_REPLY_FILE=/work/stub-reply.md\n"
        )
    else:
        model = real["AIRLOCK_MODEL"]
        lines = {
            "AIRLOCK_SECRET": secret["INFRA"],
            "AIRLOCK_ENGINE": "claude",
            "AIRLOCK_MODEL": model,
            "AIRLOCK_MAX_BUDGET_USD": "1",
            "AIRLOCK_MAX_TURNS": "25",
            "AIRLOCK_TIMEOUT_SECONDS": "600",
            "ANTHROPIC_BASE_URL": real["ANTHROPIC_BASE_URL"],
            "ANTHROPIC_AUTH_TOKEN": real["ANTHROPIC_AUTH_TOKEN"],
            "ANTHROPIC_MODEL": model,
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": model,
            "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
            "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
            "CLAUDE_CODE_SUBAGENT_MODEL": model,
            "DISABLE_AUTOUPDATER": "1",
            "DISABLE_TELEMETRY": "1",
            "DISABLE_ERROR_REPORTING": "1",
        }
        (root / "investigator-infra.env").write_text("".join(f"{k}={v}\n" for k, v in lines.items()))
        for name, content in EVIDENCE.items():
            (root / "work" / "infra" / name).parent.mkdir(parents=True, exist_ok=True)
            (root / "work" / "infra" / name).write_text(content)
        (root / "profiles" / "skills-infra" / "pool-exhaustion").mkdir(parents=True, exist_ok=True)
        (root / "profiles" / "skills-infra" / "pool-exhaustion" / "SKILL.md").write_text(SKILL)
    (root / "investigator-code.env").write_text(f"AIRLOCK_SECRET={secret['CODE']}\nAIRLOCK_ENGINE=stub\n")
    (root / "profiles" / "infra.md").write_text(REAL_INSTRUCTIONS if real else "Smoke test profile.\n")
    (root / "profiles" / "posture-infra.yaml").write_text("[]\n")
    (root / "profiles" / "mcp-infra.json").write_text('{"mcpServers": {}}\n')
    # A gateway in front of a server that is not there: the smoke checks the wiring, scripts/mcpgate_check.py the protocol.
    gate = {
        "servers": {"demo": {"url": "http://127.0.0.1:9/mcp", "tools": ["deploy_history"]}},
        "clients": {"infra": {"token_env": "AIRLOCK_MCPGATE_INFRA_TOKEN", "servers": ["demo"]}},
    }
    (root / "mcp-gate.json").write_text(json.dumps(gate))
    (root / "mcp-gate.env").write_text(f"AIRLOCK_MCPGATE_INFRA_TOKEN={secrets.token_hex(24)}\n")
    (root / "work" / "infra" / "stub-reply.md").write_text(REPLY)
    return secret


def state_of(db: Path, work_id: str) -> str:
    with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as conn:
        row = conn.execute("SELECT state FROM work_items WHERE id = ?", [work_id]).fetchone()
    return row[0] if row else "missing"


def wait_for(predicate: Any, what: str, within: float = 120) -> Any:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(1)
    raise SystemExit(f"compose smoke: timed out waiting for {what}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--engine", choices=("stub", "claude"), default="stub")
    args = parser.parse_args()
    real = None
    if args.engine == "claude":
        names = ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "AIRLOCK_MODEL")
        missing = [n for n in names if not os.environ.get(n)]
        if missing:
            raise SystemExit(f"compose smoke: --engine claude needs {', '.join(missing)}")
        real = {n: os.environ[n] for n in names}
    gateway = urlparse(real["ANTHROPIC_BASE_URL"]).hostname if real else "api.github.com"
    hide = [v for v in (real or {}).values() if v] + ([gateway] if real else [])

    def masked(text: str) -> str:
        for value in hide:
            text = text.replace(value, "[hidden]")
        return text

    tag = secrets.token_hex(3)
    root = ROOT / "data" / f"compose-{time.strftime('%Y%m%d-%H%M%S')}"
    project = f"airlock-smoke-{tag}"
    port = free_port()
    env = {
        **os.environ,
        "AIRLOCK_ROOT": str(root),
        "AIRLOCK_IMAGE": "airlock:dev",
        "AIRLOCK_LAUNCHER_IMAGE": "airlock-launcher:dev",
        "AIRLOCK_INVESTIGATOR_IMAGE": "airlock-investigator:dev" if real else "airlock:dev",
        **({"AIRLOCK_EGRESS_ALLOW": str(gateway)} if real else {}),
        "AIRLOCK_CONSOLE_PORT": str(port),
        "DOCKER_GID": os.environ.get("DOCKER_GID", "0"),
        "COMPOSE_PROFILES": "mcp-gate",
    }
    compose = [
        "docker",
        "compose",
        "-f",
        str(ROOT / "deploy" / "compose.yml"),
        "--project-directory",
        str(root),
        "-p",
        project,
    ]
    print("building images")
    run("docker", "build", "-q", "-f", str(ROOT / "deploy" / "Dockerfile"), "-t", "airlock:dev", str(ROOT))
    run(
        "docker",
        "build",
        "-q",
        "-f",
        str(ROOT / "deploy" / "Dockerfile.launcher"),
        "--build-arg",
        "BASE=airlock:dev",
        "-t",
        "airlock-launcher:dev",
        str(ROOT),
    )
    if real:
        run(
            "docker",
            "build",
            "-q",
            "-f",
            str(ROOT / "deploy" / "Dockerfile.investigator"),
            "--build-arg",
            "BASE=airlock:dev",
            "-t",
            "airlock-investigator:dev",
            str(ROOT),
        )
    root.mkdir(parents=True)
    secret = lay_out(root, port, real)
    results: dict[str, Any] = {}
    try:
        print(f"starting compose project {project}")
        run(*compose, "up", "-d", env=env)
        base = f"http://127.0.0.1:{port}"
        wait_for(lambda: _healthy(base), "the console")
        body = json.dumps(
            {"status": "firing", "alertname": "HighErrorRate", "description": "demo/api 5xx", "fingerprint": tag}
        ).encode()
        work_id = httpx.post(f"{base}/v1/intake/alerts", content=body, headers=sign(secret["ALERTS"], body)).json()[
            "work_id"
        ]
        db = root / "data" / "control.db"
        wait_for(lambda: state_of(db, work_id) == "plan_ready", "the investigator's plan", within=600 if real else 120)
        with httpx.Client(base_url=base, follow_redirects=False) as web:
            web.post("/login", data={"password": PASSWORD})
            page = web.get(f"/work/{work_id}").text
            fields = {
                name: re.search(rf'name="{name}" value="([^"]+)"', page).group(1)
                for name in ("csrf", "version", "plan_hash")
            }  # type: ignore[union-attr]
            web.post(f"/work/{work_id}/approve", data=fields)
        final = wait_for(
            lambda: (s := state_of(db, work_id)) in ("done", "failed", "refused") and s, "the run", within=180
        )
        with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as conn:
            approval, result = conn.execute(
                "SELECT approval_id, result FROM runs WHERE work_id = ?", [work_id]
            ).fetchone()
        report = json.loads(result)
        log = root / "runs" / approval / "group-1" / "step-1.log"
        results = {
            "state": final,
            "isolation": report.get("isolation"),
            "record_intact": all(g.get("record_intact") for g in report.get("groups") or []),
            "worker_output": log.read_text().strip() if log.exists() else None,
        }
        probe = run(
            *compose,
            "exec",
            "-T",
            "investigator-infra",
            "python",
            "-c",
            NETWORK_PROBE,
            str(gateway),
            env=env,
            check=False,
        )
        results["network"] = dict(line.split(": ", 1) for line in probe.stdout.strip().splitlines() if ": " in line)
        if probe.returncode != 0:
            results["network_error"] = masked(probe.stderr[-300:])
        other = run(
            *compose,
            "exec",
            "-T",
            "investigator-code",
            "python",
            "-c",
            "import socket\ntry:\n socket.getaddrinfo('mcp-gate', 8097); print('reachable')\n"
            "except socket.gaierror:\n print('does not resolve')",
            env=env,
            check=False,
        )
        results["code_sees_mcp_gate"] = other.stdout.strip() or masked(other.stderr[-300:])
        if real:
            proxy_log = run(*compose, "logs", "--no-color", "egress", env=env, check=False)
            results["model_calls_through_proxy"] = f"allowed {gateway}:443" in (proxy_log.stdout + proxy_log.stderr)
            with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as conn:
                plan = conn.execute(
                    "SELECT plan FROM plans WHERE work_id = ? ORDER BY version DESC LIMIT 1", [work_id]
                ).fetchone()
            results["plan_steps"] = (
                [" ".join(s.get("argv") or []) for s in json.loads(plan[0])["steps"]] if plan else []
            )
    finally:
        logs = run(*compose, "logs", "--no-color", "--tail", "40", env=env, check=False).stdout
        (ROOT / "data" / f"compose-smoke-{tag}.log").write_text(masked(logs))
        run(*compose, "down", "-v", "--remove-orphans", env=env, check=False)
        subprocess.run(["rm", "-rf", str(root)], check=False, capture_output=True)
        if root.exists():
            # Files the containers wrote belong to their users (uid 10001, root for
            # mount points); on a Linux host only root can take them away.
            run(
                "docker",
                "run",
                "--rm",
                "--user",
                "0",
                "-v",
                f"{root.parent}:/cleanup",
                "airlock:dev",
                "rm",
                "-rf",
                f"/cleanup/{root.name}",
                check=False,
            )
    print(json.dumps(results, indent=2, ensure_ascii=False))
    network = results.get("network", {})
    ok = (
        results.get("state") == "done"
        and results.get("isolation") == "container"
        and results.get("record_intact")
        and (real is not None or results.get("worker_output") == "rollout restart deployment/api")
        and (real is None or results.get("model_calls_through_proxy") is True)
        and network.get("launcher") == "does not resolve"
        and network.get("internet") == "unreachable"
        and str(network.get("listed", "")).startswith("HTTP/1.1 200")
        and str(network.get("unlisted", "")).startswith("HTTP/1.1 403")
        and network.get("mcp gate") == "reachable"
        and network.get("mcp gate health") == "200"
        and results.get("code_sees_mcp_gate") == "does not resolve"
    )
    print("compose smoke:", "PASS" if ok else f"FAIL (logs in data/compose-smoke-{tag}.log)")
    return 0 if ok else 1


def _healthy(base: str) -> bool:
    try:
        return httpx.get(f"{base}/healthz", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


if __name__ == "__main__":
    sys.exit(main())
