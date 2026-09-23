"""The pieces around the core, run as deploy/compose.yml runs them, with a real model judging a made-up chat.

    python scripts/extras_smoke.py

What runs: the compose file's core, plus the MCP gateway, the watcher, the chat
adapter and the self-check, each under its compose profile. Two smoke-only
services come from deploy/smoke/compose.smoke.yml:
- a made-up chat platform's MCP server;
- a stand-in for a custom bot's webhook, which records every card.

What it proves:
1. The watcher reads the chat through the gateway. Its first round lays the
   floor and says nothing.
2. The smoke adds messages. On the next round, the judge sees them: the real
   model through the Claude Code CLI, with no built-in tools, out through the
   egress proxy only.
3. A task the judge raises reaches the intake signed by the watcher and becomes
   a work item. The investigator (a stub here) answers it with a plan.
4. The chat adapter turns the outlet's plan.ready and the watcher's notices
   into cards.
5. The self-check finds every health endpoint up, the model answering, and the
   watcher's last round clean.

The model settings come from the environment (ANTHROPIC_BASE_URL,
ANTHROPIC_AUTH_TOKEN, AIRLOCK_MODEL). Everything is laid out under
data/compose-<time>/ in a compose project named airlock-extras-<random>, and
all of it is removed at the end, pass or fail.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compose_smoke as base  # noqa: E402 — the same layout and helpers as the core smoke

ROOT = base.ROOT
BRIEF = (
    "你替我盯着工作群。只报需要我亲自处理或回答的事：直接问我的问题、派给我的活、需要我处理的故障。\n"
    "闲聊、吃饭、表情、一句确认都不报。我叫 Sam。\n"
)
EVENTS = ["plan.ready", "plan.revised", "work.answered", "run.finished", "run.failed", "work.error"]


def main() -> int:
    names = ("ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "AIRLOCK_MODEL")
    missing = [n for n in names if not os.environ.get(n)]
    if missing:
        raise SystemExit(f"extras smoke: needs {', '.join(missing)}")
    model = {n: os.environ[n] for n in names}
    gateway = str(urlparse(model["ANTHROPIC_BASE_URL"]).hostname)
    hide = [*model.values(), gateway]

    def masked(text: str) -> str:
        for value in hide:
            text = text.replace(value, "[hidden]")
        return text

    tag = secrets.token_hex(3)
    root = ROOT / "data" / f"compose-{time.strftime('%Y%m%d-%H%M%S')}"
    project, port = f"airlock-extras-{tag}", base.free_port()
    env = {
        **os.environ,
        "AIRLOCK_ROOT": str(root),
        "AIRLOCK_IMAGE": "airlock:dev",
        "AIRLOCK_LAUNCHER_IMAGE": "airlock-launcher:dev",
        "AIRLOCK_INVESTIGATOR_IMAGE": "airlock-investigator:dev",
        "AIRLOCK_FEISHU_IMAGE": "airlock-feishu:dev",
        "AIRLOCK_EGRESS_ALLOW": gateway,
        "AIRLOCK_CONSOLE_PORT": str(port),
        "DOCKER_GID": os.environ.get("DOCKER_GID", "0"),
        "COMPOSE_PROFILES": "mcp-gate,watch,feishu,selfcheck",
    }
    compose = [
        "docker",
        "compose",
        "-f",
        str(ROOT / "deploy" / "compose.yml"),
        "-f",
        str(ROOT / "deploy" / "smoke" / "compose.smoke.yml"),
        "--project-directory",
        str(root),
        "-p",
        project,
    ]
    print("building images")
    for dockerfile, image in (
        ("Dockerfile", "airlock:dev"),
        ("Dockerfile.launcher", "airlock-launcher:dev"),
        ("Dockerfile.investigator", "airlock-investigator:dev"),
        ("Dockerfile.feishu", "airlock-feishu:dev"),
    ):
        base.run(
            "docker", "build", "-q", "-f", str(ROOT / "deploy" / dockerfile),
            "--build-arg", "BASE=airlock:dev", "-t", image, str(ROOT),
        )  # fmt: skip
    root.mkdir(parents=True)
    secret = base.lay_out(root, port, None)
    lay_out_extras(root, model, secret)
    results: dict[str, Any] = {}
    db = root / "data" / "control.db"
    try:
        print(f"starting compose project {project}")
        base.run(*compose, "up", "-d", env=env)
        base.wait_for(lambda: base._healthy(f"http://127.0.0.1:{port}"), "the console")

        def inside(service: str, *argv: str) -> subprocess.CompletedProcess[str]:
            return base.run(*compose, "exec", "-T", service, *argv, env=env, check=False)

        def watch_round() -> dict[str, Any]:
            done = inside(
                "watch",
                "python",
                "-m",
                "airlock.extras.watch",
                "--config",
                "/etc/airlock/watch.yaml",
                "--once",
                "--force",
            )
            start = done.stdout.find("{")
            return (
                json.loads(done.stdout[start:])
                if start >= 0
                else {"outcome": "no output", "stderr": masked(done.stderr[-400:])}
            )

        base.wait_for(
            lambda: inside("feishu", "python", "-c", PROBE, "http://127.0.0.1:9100/healthz").returncode == 0,
            "the adapter",
        )
        base.wait_for(
            lambda: inside("fake-chat", "python", "-c", PROBE, "http://127.0.0.1:9200/healthz").returncode == 0,
            "the chat",
        )
        results["first_round"] = watch_round().get("outcome")
        for feed, who, text in (
            ("ops-team", "Lena", "@Sam the payments deploy to staging failed twice with a migration lock timeout — can you take a look this afternoon? It blocks the release."),
            ("ops-team", "Lena", "👍"),
            ("lunch", "Tom", "the noodle place is closed today lol"),
            ("lunch", "Ada", "haha ok, dumplings then"),
        ):  # fmt: skip
            said = json.dumps({"feed": feed, "who": who, "text": text, "ago": 30})
            inside("fake-chat", "python", "-c", SAY, said)
        second = watch_round()
        results["second_round"] = {
            "outcome": second.get("outcome"),
            "offered": second.get("offered"),
            "judge": {k: v for k, v in (second.get("judge") or {}).items() if k in ("signals", "dropped", "error")},
            "deliveries": [{k: d[k] for k in ("door", "kind", "ok", "title")} for d in second.get("deliveries") or []],
        }

        def watch_item() -> dict[str, Any] | None:
            with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT id, title, state, labels FROM work_items WHERE labels LIKE '%watch%'"
                ).fetchone()
            return dict(row) if row and row["state"] == "plan_ready" else None

        item = base.wait_for(watch_item, "the watcher's work item to get its plan", within=180)
        results["work_item"] = {"title": item["title"], "state": item["state"]}
        cards_file = root / "data" / "sink" / "cards.jsonl"

        def cards() -> list[dict[str, Any]] | None:
            if not cards_file.exists():
                return None
            found = [json.loads(line) for line in cards_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            titles = [c["card"]["header"]["title"]["content"] for c in found]
            return found if any(t.startswith("方案待批准") for t in titles) else None

        sent = base.wait_for(cards, "the plan card", within=120)
        results["cards"] = [c["card"]["header"]["title"]["content"][:80] for c in sent]
        # The self-check's own loop checks every minute. Its first tick ran while everything else was
        # still starting; wait for a tick after the flow and read what that one found.
        flow_done = time.time()
        state_file = root / "state" / "selfcheck" / "selfcheck.json"

        def checked() -> dict[str, Any] | None:
            try:
                found = json.loads(state_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return None
            fresh = len(found) == 7 and all(float(row.get("last_run") or 0) > flow_done for row in found.values())
            return found if fresh else None

        state = base.wait_for(checked, "a self-check tick after the flow", within=150)
        results["selfcheck"] = {
            name: {"ok": not row.get("fails"), "detail": masked(str(row.get("detail")))} for name, row in state.items()
        }
        proxy = base.run(*compose, "logs", "--no-color", "egress", env=env, check=False)
        results["model_calls_through_proxy"] = f"allowed {gateway}:443" in (proxy.stdout + proxy.stderr)
    finally:
        logs = base.run(*compose, "logs", "--no-color", "--tail", "60", env=env, check=False).stdout
        (ROOT / "data" / f"extras-smoke-{tag}.log").write_text(masked(logs))
        base.run(*compose, "down", "-v", "--remove-orphans", env=env, check=False)
        subprocess.run(["rm", "-rf", str(root)], check=False, capture_output=True)
        if root.exists():
            base.run(
                "docker", "run", "--rm", "--user", "0", "-v", f"{root.parent}:/cleanup", "airlock:dev",
                "rm", "-rf", f"/cleanup/{root.name}", check=False,
            )  # fmt: skip
    print(json.dumps(results, indent=2, ensure_ascii=False))
    deliveries = (results.get("second_round") or {}).get("deliveries") or []
    ok = (
        results.get("first_round") == "quiet"
        and (results.get("second_round") or {}).get("outcome") == "fired"
        and any(d["door"] == "tasks" and d["ok"] for d in deliveries)
        and all(d["ok"] for d in deliveries)
        and (results.get("work_item") or {}).get("state") == "plan_ready"
        and any(t.startswith("方案待批准") for t in results.get("cards") or [])
        and any(t.startswith("交给调查员") for t in results.get("cards") or [])
        and results.get("selfcheck")
        and all(row["ok"] for row in results["selfcheck"].values())
        and results.get("model_calls_through_proxy") is True
    )
    print("extras smoke:", "PASS" if ok else f"FAIL (logs in data/extras-smoke-{tag}.log)")
    return 0 if ok else 1


PROBE = "import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=3)"
SAY = (
    "import sys, urllib.request; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:9200/say', "
    "data=sys.argv[1].encode(), headers={'Content-Type': 'application/json'}), timeout=5)"
)


def lay_out_extras(root: Path, model: dict[str, str], secret: dict[str, str]) -> None:
    """The extras' files on top of the core smoke's layout, with fresh secrets."""
    keys = {n: secrets.token_hex(24) for n in ("WATCH", "NOTICE", "SUB", "ADAPTER", "INTAKE", "GATE")}
    for sub in ("state/watch", "state/feishu", "state/selfcheck", "data/sink"):
        (root / sub).mkdir(parents=True, exist_ok=True)
        (root / sub).chmod(0o777)  # the containers run as uid 10001
    (root / "smoke").mkdir()
    for name in ("fake_chat.py", "sink.py"):
        shutil.copy(ROOT / "deploy" / "smoke" / name, root / "smoke" / name)
    config = json.loads((root / "config.yaml").read_text())
    config["sources"] += [
        {
            "name": "watch",
            "verify": "hmac",
            "secret_env": "AIRLOCK_WATCH_SECRET",
            "accept": [{}],
            "map": {"title": "{title}", "body": "{detail}\n\n来源：{origin}", "key": "{key}"},
            "labels": ["watch"],
        },
        {
            "name": "feishu",
            "verify": "hmac",
            "secret_env": "AIRLOCK_FEISHU_INTAKE_SECRET",
            "accept": [{}],
            "map": {"title": "{title}", "body": "{detail}", "key": "{key}"},
        },
    ]
    config["subscriptions"] = [
        {
            "name": "feishu",
            "url": "http://feishu:9100/airlock",
            "secret_env": "AIRLOCK_SUB_FEISHU_SECRET",
            "events": EVENTS,
        }
    ]
    config["adapters"] = [{"name": "feishu", "secret_env": "AIRLOCK_ADAPTER_FEISHU_SECRET", "identities": ["ou_smoke"]}]
    (root / "config.yaml").write_text(json.dumps(config, indent=2))
    with (root / "control.env").open("a") as handle:
        handle.write(
            f"AIRLOCK_WATCH_SECRET={keys['WATCH']}\nAIRLOCK_SUB_FEISHU_SECRET={keys['SUB']}\n"
            f"AIRLOCK_ADAPTER_FEISHU_SECRET={keys['ADAPTER']}\nAIRLOCK_FEISHU_INTAKE_SECRET={keys['INTAKE']}\n"
        )
    tools = ["demo.list_folder_feeds", "demo.search_chat_records", "demo.search_contact"]
    gate = {
        "servers": {"chat": {"url": "http://fake-chat:9200/mcp/", "tools": tools}},
        "clients": {"watch": {"token_env": "AIRLOCK_MCPGATE_WATCH_TOKEN", "servers": ["chat"]}},
    }
    (root / "mcp-gate.json").write_text(json.dumps(gate))
    (root / "mcp-gate.env").write_text(f"AIRLOCK_MCPGATE_WATCH_TOKEN={keys['GATE']}\n")
    watch = {
        "name": "watch",
        "state_dir": "/state",
        "brief_file": "/etc/airlock/watch-brief.md",
        # A window that never comes round: the smoke runs its rounds itself.
        "schedule": {"every_minutes": 1440, "window": "00:00-00:01", "days": "1-1"},
        "chat": {
            "url": "http://mcp-gate:8097/chat/",
            "token_env": "AIRLOCK_WATCH_CHAT_TOKEN",
            "tool_prefix": "demo.",
            "me": "Sam",
        },
        "judge": {"max_budget_usd": 0.3},
        "tasks": {"url": "http://control:8080/v1/intake/watch", "secret_env": "AIRLOCK_WATCH_SECRET"},
        "notes": {"url": "http://feishu:9100/notice", "secret_env": "AIRLOCK_WATCH_NOTICE_SECRET"},
    }
    (root / "watch.yaml").write_text(json.dumps(watch))
    (root / "profiles" / "watch-brief.md").write_text(BRIEF)
    engine = "".join(f"{k}={v}\n" for k, v in model.items())
    engine += "".join(
        f"{k}={model['AIRLOCK_MODEL']}\n"
        for k in (
            "ANTHROPIC_MODEL",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL",
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "CLAUDE_CODE_SUBAGENT_MODEL",
        )
    )
    (root / "watch.env").write_text(
        engine + f"AIRLOCK_WATCH_SECRET={keys['WATCH']}\nAIRLOCK_WATCH_NOTICE_SECRET={keys['NOTICE']}\n"
        f"AIRLOCK_WATCH_CHAT_TOKEN={keys['GATE']}\n"
    )
    feishu = {
        "name": "feishu",
        "webhook_url": "http://sink:9000/cards",
        "subscription_secret_env": "AIRLOCK_SUB_FEISHU_SECRET",
        "notice_secret_env": "AIRLOCK_WATCH_NOTICE_SECRET",
        "airlock": {"console_url": "http://127.0.0.1:8080"},
        "state": "/state/feishu.db",
    }
    (root / "feishu.yaml").write_text(json.dumps(feishu))
    (root / "feishu.env").write_text(
        f"AIRLOCK_SUB_FEISHU_SECRET={keys['SUB']}\nAIRLOCK_WATCH_NOTICE_SECRET={keys['NOTICE']}\n"
    )
    selfcheck = {
        "every_minutes": 1,
        "state": "/state/selfcheck.json",
        "alarm": {"url": "http://sink:9000/alarms"},
        "checks": [
            {"name": "control", "url": "http://control:8080/healthz"},
            {"name": "launcher", "url": "http://launcher:8090/healthz"},
            {"name": "investigator infra", "url": "http://investigator-infra:8100/healthz"},
            {"name": "mcp gate", "url": "http://mcp-gate:8097/healthz"},
            {"name": "chat adapter", "url": "http://feishu:9100/healthz"},
            {"name": "watcher", "watcher_status": "/watch/status.json"},
            {"name": "model", "model": True},
        ],
    }
    (root / "selfcheck.yaml").write_text(json.dumps(selfcheck))
    (root / "selfcheck.env").write_text(engine)


if __name__ == "__main__":
    sys.exit(main())
