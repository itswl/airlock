"""What a person's message in the chat becomes. Decided by structure — where it was posted, by whom — never by its text.

| the message | becomes |
|---|---|
| a reply under a work item's card | your message on that item (``/v1/adapters/<name>/message``); the investigator revises |
| a reply that is only 有用 or 没用, under a work item's card | your rating of that item (``/v1/adapters/<name>/rating``) |
| a reply under a watcher's note | a new work item (the adapter's intake source), the note as its context |
| a new topic that @-mentions the bot | a new work item |
| from anyone not in ``people``, from a bot, from another chat | nothing, and a log line |

A message is handled once however often the platform redelivers it. airlock
checks the person again on its side (the adapter's ``identities``), so a
mistake here cannot let somebody else speak for you.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from typing import Any

import httpx

from airlock.crypto import sign
from airlock.extras.feishu.app import Cards
from airlock.extras.feishu.config import FeishuConfig

logger = logging.getLogger("airlock.feishu")
_MENTION = re.compile(r"@_user_\d+\s*")
RATING = re.compile(r"(有用|没用)[。.!！]*")


def text_of(message: dict[str, Any]) -> str:
    """The words of a text or rich-text message, mentions taken out."""
    try:
        content = json.loads(message.get("content") or "{}")
    except ValueError:
        return ""
    if message.get("message_type") == "post":
        body = content.get("content") or next((v.get("content") for v in content.values() if isinstance(v, dict)), [])
        words = [str(n.get("text") or "") for line in body or [] for n in line if isinstance(n, dict)]
        text = " ".join(w for w in words if w)
    else:
        text = str(content.get("text") or "")
    return _MENTION.sub("", text).strip()


def _post(client: httpx.Client, url: str, secret: str, payload: dict[str, Any]) -> tuple[int | None, str]:
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode()
    try:
        response = client.post(url, content=body, headers={**sign(secret, body), "Content-Type": "application/json"})
    except httpx.HTTPError as exc:
        return None, f"{type(exc).__name__}: {str(exc)[:160]}"
    return response.status_code, response.text[:300]


def handle(
    config: FeishuConfig,
    cards: Cards,
    event: dict[str, Any],
    *,
    client: httpx.Client | None = None,
    clock: Callable[[], float] = time.time,
) -> str:
    """One ``im.message.receive_v1`` event (as a dict). Returns what was done, for the log and the tests."""
    message, sender = event.get("message") or {}, event.get("sender") or {}
    message_id = str(message.get("message_id") or "")
    if not message_id:
        return "ignored: no message id"
    if cards.db.one("SELECT 1 FROM inbound WHERE message_id = ?", [message_id]):
        return "ignored: already handled"
    outcome = _handle(config, cards, message, sender, client or httpx.Client(timeout=30.0))
    cards.db.execute(
        "INSERT OR IGNORE INTO inbound (message_id, at, outcome) VALUES (?,?,?)", [message_id, clock(), outcome]
    )
    logger.info("message %s: %s", message_id, outcome)
    return outcome


def _handle(
    config: FeishuConfig, cards: Cards, message: dict[str, Any], sender: dict[str, Any], client: httpx.Client
) -> str:
    if sender.get("sender_type") != "user":
        return "ignored: not a person"
    chat = str(message.get("chat_id") or "")
    if chat not in {config.plans_chat, config.notices_chat}:
        return "ignored: not one of this adapter's chats"
    user = str((sender.get("sender_id") or {}).get("open_id") or "")
    if user not in config.people:
        return "ignored: this person is not one who may speak through the adapter"
    text = text_of(message)
    if not text:
        return "ignored: no text"
    root = str(message.get("root_id") or message.get("parent_id") or "")
    card = cards.card(root) if root else None
    if card is not None and card["kind"] == "work" and card["work_id"]:
        if not config.adapter_url:
            return "ignored: no adapter door configured"
        verdict = RATING.fullmatch(text)
        if verdict is not None:
            # Only the bare word is a rating; "没用，再查查" is a message to the investigator.
            status, reply = _post(
                client,
                f"{config.adapter_url}/rating",
                config.adapter_secret,
                {
                    "work_id": card["work_id"],
                    "rating": "useful" if verdict.group(1) == "有用" else "useless",
                    "platform_user": user,
                },
            )
            return f"rating on {card['work_id']}: {status}" + ("" if status == 200 else f" {reply}")
        status, reply = _post(
            client,
            f"{config.adapter_url}/message",
            config.adapter_secret,
            {"work_id": card["work_id"], "text": text, "platform_user": user},
        )
        return f"message on {card['work_id']}: {status}" + ("" if status == 200 else f" {reply}")
    if root and card is None:
        return "ignored: a reply under a card this adapter did not send"
    if not config.intake_url:
        return "ignored: no intake door configured"
    note = json.loads(card["notice"]) if card is not None and card["notice"] else {}
    context = (
        f"{note.get('title', '')}\n{note.get('detail', '')}\n来源：{note.get('origin', '')}".strip() if note else ""
    )
    status, reply = _post(
        client,
        config.intake_url,
        config.intake_secret,
        {
            "title": text[:200],
            "detail": f"{text}\n\n---\n{context}" if context else text,
            "origin": "feishu / reply" if note else "feishu / topic",
            "platform_user": user,
            "message_id": str(message.get("message_id") or ""),
            "key": str(message.get("message_id") or ""),
        },
    )
    return f"new work item: {status}" + ("" if status and status < 300 else f" {reply}")


def listen(config: FeishuConfig, cards: Cards) -> None:
    """Hold the application's long connection and hand every message to ``handle``. Blocks."""
    import lark_oapi as lark

    client = httpx.Client(timeout=30.0)

    def on_message(data: Any) -> None:
        event = json.loads(lark.JSON.marshal(data)).get("event") or {}
        try:
            handle(config, cards, event, client=client)
        except Exception:  # noqa: BLE001 — one bad message must not drop the connection
            logger.exception("handling a message failed")

    handler = lark.EventDispatcherHandler.builder("", "").register_p2_im_message_receive_v1(on_message).build()
    domain = lark.LARK_DOMAIN if config.brand == "lark" else lark.FEISHU_DOMAIN
    # WARNING, not INFO: at INFO the SDK logs the connection URL, access key included.
    lark.ws.Client(
        config.app_id, config.app_secret, event_handler=handler, domain=domain, log_level=lark.LogLevel.WARNING
    ).start()
