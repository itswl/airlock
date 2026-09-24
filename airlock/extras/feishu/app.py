"""The adapter's two doors in (the outlet, the watcher's notes) and its one table of which card is which."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from typing import Any, Protocol

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from airlock import __version__
from airlock.crypto import SignatureError, verify
from airlock.db import Database
from airlock.extras.feishu import render
from airlock.extras.feishu.config import FeishuConfig
from airlock.extras.feishu.lark import LarkError

logger = logging.getLogger("airlock.feishu")
# Between the pieces of a report: the platform limits how fast one chat is sent to (5 a second).
PIECE_PAUSE_SECONDS = 0.25

SCHEMA = """
CREATE TABLE IF NOT EXISTS deliveries (id TEXT PRIMARY KEY, event TEXT NOT NULL, at REAL NOT NULL, message_id TEXT);
CREATE TABLE IF NOT EXISTS threads (work_id TEXT PRIMARY KEY, chat_id TEXT NOT NULL, root TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cards (
    message_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,          -- work | notice
    work_id TEXT,
    notice TEXT,                 -- the note's JSON, for a reply that turns it into work
    at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS inbound (message_id TEXT PRIMARY KEY, at REAL NOT NULL, outcome TEXT NOT NULL);
"""


class Sender(Protocol):
    def send(self, chat_id: str, card: dict[str, Any]) -> str: ...
    def reply(self, message_id: str, card: dict[str, Any]) -> str: ...


class Cards:
    """Which card belongs to which work item, and which thread a work item's cards go into."""

    def __init__(self, config: FeishuConfig, sender: Sender, *, clock: Callable[[], float] = time.time) -> None:
        self.config, self.sender, self.clock = config, sender, clock
        self.db = Database(str(config.state))
        self.db.script(SCHEMA)

    def post_for_work(self, work_id: str, card: dict[str, Any]) -> str:
        thread = self.db.one("SELECT * FROM threads WHERE work_id = ?", [work_id]) if work_id else None
        if thread is not None:
            message_id = self.sender.reply(thread["root"], card)
        else:
            message_id = self.sender.send(self.config.plans_chat, card)
            if message_id and work_id:
                self.db.execute(
                    "INSERT OR IGNORE INTO threads (work_id, chat_id, root) VALUES (?,?,?)",
                    [work_id, self.config.plans_chat, message_id],
                )
        if message_id:
            self.db.execute(
                "INSERT OR REPLACE INTO cards (message_id, kind, work_id, at) VALUES (?, 'work', ?, ?)",
                [message_id, work_id, self.clock()],
            )
        return message_id

    def post_notice(self, notice: dict[str, Any], card: dict[str, Any]) -> str:
        message_id = self.sender.send(self.config.notices_chat, card)
        if message_id:
            self.db.execute(
                "INSERT OR REPLACE INTO cards (message_id, kind, work_id, notice, at) VALUES (?, 'notice', ?, ?, ?)",
                [message_id, notice.get("work_id"), json.dumps(notice, ensure_ascii=False), self.clock()],
            )
        return message_id

    def card(self, message_id: str) -> dict[str, Any] | None:
        return self.db.one("SELECT * FROM cards WHERE message_id = ?", [message_id])


def create_app(config: FeishuConfig, cards: Cards, *, clock: Callable[[], float] = time.time) -> FastAPI:
    app = FastAPI(title="airlock feishu adapter", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)

    def signed(secret: str, body: bytes, headers: Any) -> dict[str, Any]:
        if not secret:
            raise HTTPException(404, "this door is not configured")
        try:
            verify(secret, body, headers, now=clock())
        except SignatureError as exc:
            raise HTTPException(401, str(exc)) from exc
        try:
            data = json.loads(body)
        except ValueError as exc:
            raise HTTPException(400, "the body is not JSON") from exc
        if not isinstance(data, dict):
            raise HTTPException(400, "the body is not a JSON object")
        return data

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "cards": (cards.db.one("SELECT COUNT(*) AS n FROM cards") or {}).get("n", 0)}

    @app.post("/airlock")
    async def outlet(request: Request) -> JSONResponse:
        envelope = signed(config.subscription_secret, await request.body(), request.headers)
        delivery, event = str(envelope.get("id") or ""), str(envelope.get("event") or "")
        payload = envelope.get("payload") if isinstance(envelope.get("payload"), dict) else {}
        if delivery and cards.db.one("SELECT 1 FROM deliveries WHERE id = ?", [delivery]):
            return JSONResponse({"status": "already sent"})
        card = render.for_event(event, payload)
        message_id = None
        if card is not None:
            try:
                message_id = cards.post_for_work(str(payload.get("work_id") or ""), card)
            except LarkError as exc:
                logger.warning("sending %s failed: %s", event, exc)
                return JSONResponse({"reason": str(exc)}, status_code=502)  # the outlet retries, then dead-letters
        if delivery:
            cards.db.execute(
                "INSERT OR IGNORE INTO deliveries (id, event, at, message_id) VALUES (?,?,?,?)",
                [delivery, event, clock(), message_id],
            )
        # Then the whole report, into the card's thread: the card's button opens a console a phone may not reach.
        # A failure here is logged, not retried: the card is out, and a retry would send it twice.
        sent = 0
        for extra in render.report_cards(event, payload) if card is not None else []:
            if sent:
                time.sleep(PIECE_PAUSE_SECONDS)
            try:
                cards.post_for_work(str(payload.get("work_id") or ""), extra)
                sent += 1
            except LarkError as exc:
                logger.warning("sending the report of %s failed after %d cards: %s", payload.get("work_id"), sent, exc)
                break
        return JSONResponse(
            {"status": "sent" if card else "no card for this event", "message_id": message_id, "report_cards": sent}
        )

    @app.post("/notice")
    async def notice(request: Request) -> JSONResponse:
        note = signed(config.notice_secret, await request.body(), request.headers)
        if not str(note.get("title") or "").strip():
            raise HTTPException(400, "a notice has a title")
        if note.get("work_id") and config.console_url:
            note["link"] = f"{config.console_url}/work/{note['work_id']}"
        try:
            message_id = cards.post_notice(note, render.for_notice(note))
        except LarkError as exc:
            logger.warning("sending a notice failed: %s", exc)
            return JSONResponse({"reason": str(exc)}, status_code=502)
        return JSONResponse({"status": "sent", "message_id": message_id})

    return app
