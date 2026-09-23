"""A made-up chat platform's MCP server, for scripts/extras_smoke.py only. Three read tools, answered as an event stream.

POST /say {"feed", "who", "text"} adds a message now; the smoke uses it from inside the container.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

PREFIX = "demo."
messages: dict[str, list[dict]] = {}
app = FastAPI()


def iso(at: float) -> str:
    return datetime.fromtimestamp(at, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def say(feed: str, who: str, text: str, at: float) -> None:
    messages.setdefault(feed, []).append(
        {"send_at": iso(at), "send_name": who, "content": text, "message_type": "text"}
    )


say("ops-team", "Lena", "morning all", time.time() - 3600)
say("lunch", "Tom", "anyone for noodles?", time.time() - 3500)


@app.post("/say")
async def add(request: Request) -> dict:
    item = json.loads(await request.body())
    say(item["feed"], item["who"], item["text"], time.time() - float(item.get("ago") or 0))
    return {"ok": True}


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True}


@app.post("/mcp/")
async def mcp(request: Request) -> Response:
    message = json.loads(await request.body())
    if message.get("method") == "initialize":
        result: dict = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "demo"}}
    elif message.get("method") == "tools/list":
        result = {
            "tools": [
                {"name": PREFIX + n, "inputSchema": {"type": "object"}}
                for n in ("list_folder_feeds", "search_chat_records", "search_contact")
            ]
        }
    elif message.get("method") == "tools/call":
        tool, args = message["params"]["name"][len(PREFIX) :], message["params"].get("arguments") or {}
        if tool == "list_folder_feeds":
            structured: dict = {
                "feeds": [
                    {"name": f, "chat_type_label": "group chat", "last_message_send_at": m[-1]["send_at"]}
                    for f, m in messages.items()
                    if m
                ]
            }
        elif tool == "search_chat_records":
            lo, hi = int(args.get("from_time") or 0), int(args.get("to_time") or 2**31)
            found = [
                m
                for m in messages.get(args.get("contact_name", ""), [])
                if lo <= datetime.fromisoformat(m["send_at"].replace("Z", "+00:00")).timestamp() <= hi
            ]
            structured = {"messages": list(reversed(found))}
        else:
            structured = {"candidates": []}
        result = {"content": [{"type": "text", "text": "ok"}], "structuredContent": structured}
    else:
        return Response(status_code=202)
    body = json.dumps({"jsonrpc": "2.0", "id": message.get("id"), "result": result})
    return Response(f"event: message\ndata: {body}\n\n", media_type="text/event-stream")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9200, log_level="warning")  # noqa: S104 — a container on a smoke network
