"""The watcher end to end on a made-up chat: a real scan over HTTP, the real judge, real signed deliveries.

    python scripts/watch_check.py

A chat server made up for this check answers the platform's three read tools
over HTTP, as an event stream. It holds two conversations:
- one with a request that plainly needs the operator, a question they must
  answer, and some noise;
- one with nothing but chatter.
Signals are delivered to a local receiver that checks each signature the way
airlock's intake does.

The first round lays the floor and reports nothing. Then new messages arrive,
and the second round runs the real judge through the Claude Code CLI with no
built-in tools. The model settings come from the environment
(ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN, AIRLOCK_MODEL), as for demo.py. The
check passes when:
- the request arrives as a task;
- nothing from the chatter arrives;
- every delivery verified.
"""

from __future__ import annotations

import json
import socket
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

from airlock.crypto import SignatureError, verify
from airlock.extras.watch.__main__ import run_round
from airlock.extras.watch.config import load_watch
from airlock.extras.watch.mcp import McpClient
from airlock.extras.watch.scan import Scanner
from airlock.runner.recorder import Recorder

PREFIX = "demo."
TASKS, NOTES = "t" * 32, "n" * 32


def iso(at: float) -> str:
    return datetime.fromtimestamp(at, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Chat:
    def __init__(self) -> None:
        self.messages: dict[str, list[dict[str, Any]]] = {"ops-team": [], "lunch": []}

    def say(self, feed: str, who: str, text: str, at: float) -> None:
        self.messages[feed].append({"send_at": iso(at), "send_name": who, "content": text, "message_type": "text"})

    def feeds(self) -> list[dict[str, Any]]:
        return [
            {"name": name, "chat_type_label": "group chat", "last_message_send_at": items[-1]["send_at"]}
            for name, items in self.messages.items()
            if items
        ]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def serve(app: FastAPI, port: int) -> uvicorn.Server:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    while not server.started:
        time.sleep(0.05)
    return server


def chat_app(chat: Chat) -> FastAPI:
    app = FastAPI()

    @app.post("/mcp/")
    async def mcp(request: Request) -> Response:
        message = json.loads(await request.body())
        if message["method"] == "initialize":
            result: dict[str, Any] = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}
        else:
            tool, args = message["params"]["name"][len(PREFIX) :], message["params"]["arguments"]
            if tool == "list_folder_feeds":
                structured: Any = {"feeds": chat.feeds()}
            elif tool == "search_chat_records":
                lo, hi = int(args["from_time"]), int(args["to_time"])
                found = [
                    m
                    for m in chat.messages.get(args["contact_name"], [])
                    if lo <= datetime.fromisoformat(m["send_at"].replace("Z", "+00:00")).timestamp() <= hi
                ]
                structured = {"messages": list(reversed(found))}
            else:
                structured = {"candidates": []}
            result = {"content": [{"type": "text", "text": "ok"}], "structuredContent": structured}
        body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result})
        return Response(f"event: message\ndata: {body}\n\n", media_type="text/event-stream")

    return app


def receiver_app(received: list[dict[str, Any]]) -> FastAPI:
    app = FastAPI()

    @app.post("/{door}")
    async def door(door: str, request: Request) -> dict[str, str]:
        body = await request.body()
        try:
            verify(TASKS if door == "intake" else NOTES, body, request.headers)
            verified = True
        except SignatureError:
            verified = False
        received.append({"door": door, "verified": verified, **json.loads(body)})
        return {"status": "ok"}

    return app


def main() -> int:
    chat, received = Chat(), []
    chat_port, receiver_port = free_port(), free_port()
    servers = [serve(chat_app(chat), chat_port), serve(receiver_app(received), receiver_port)]
    now = time.time()
    chat.say("ops-team", "Lena", "morning all", now - 3600)
    chat.say("lunch", "Tom", "anyone for noodles?", now - 3500)
    with tempfile.TemporaryDirectory(prefix="watch-check-") as tmp:
        root = Path(tmp)
        (root / "brief.md").write_text(
            "你替我盯着工作群。只报需要我亲自处理或回答的事：直接问我的问题、派给我的活、需要我处理的故障。\n"
            "闲聊、吃饭、表情、一句确认都不报。拿不准就报成 low 的 note。我叫 Sam。\n",
            encoding="utf-8",
        )
        config = load_watch(
            {
                "name": "watch-check",
                "state_dir": str(root / "state"),
                "brief_file": str(root / "brief.md"),
                "chat": {"url": f"http://127.0.0.1:{chat_port}/mcp/", "tool_prefix": PREFIX, "me": "Sam"},
                "tasks": {"url": f"http://127.0.0.1:{receiver_port}/intake", "secret": TASKS},
                "notes": {"url": f"http://127.0.0.1:{receiver_port}/notice", "secret": NOTES},
                "judge": {"max_budget_usd": 0.3},
            }
        )
        scanner = Scanner(config, chat=McpClient(config.chat.url, prefix=PREFIX))
        record = Recorder(config.state_dir / "rounds.jsonl")
        first = run_round(config, scanner, record, force=True)
        later = time.time()
        chat.say(
            "ops-team",
            "Lena",
            "@Sam the payments deploy to staging failed twice with a migration lock timeout — can you take a look this afternoon? It blocks the release.",
            later - 120,
        )
        chat.say(
            "ops-team",
            "Omar",
            "Sam, are we still doing the DB failover drill on Thursday? Need a yes/no by 5pm.",
            later - 90,
        )
        chat.say("ops-team", "Lena", "👍", later - 60)
        chat.say("lunch", "Tom", "the noodle place on 5th is closed today lol", later - 50)
        chat.say("lunch", "Ada", "haha ok, dumplings then", later - 40)
        second = run_round(config, scanner, record, force=True)
    for server in servers:
        server.should_exit = True
    report = {
        "first_round": first["outcome"],
        "second_round": second["outcome"],
        "offered": second.get("offered"),
        "judge": {k: v for k, v in (second.get("judge") or {}).items() if k != "usage"},
        "received": [{k: r[k] for k in ("door", "verified", "title", "level", "kind", "origin")} for r in received],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    tasks = [r for r in received if r["door"] == "intake"]
    ok = (
        first["outcome"] == "quiet"
        and second["outcome"] == "fired"
        and all(r["verified"] for r in received)
        and any(
            "deploy" in r["title"].lower() or "migration" in r["title"].lower() or "部署" in r["title"] for r in tasks
        )
        and not any("lunch" in r["origin"] for r in received)
    )
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
