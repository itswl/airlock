"""The chat part of the scan: every conversation since its cursor, with the noise taken out.

Who writes which cursor matters, and here one process writes them all. A
conversation's cursor moves when its messages have been handed to a round:
the round decides what to report, but it cannot make a message be read twice
or never.

Rules that each came from a real round:

* ``from_time`` is inclusive on the server, so the window starts one second
  after the cursor. Passing the cursor itself once re-sent a five-hour-old
  @-everyone as new.
* Threads are not conversations. Several of them can share one name
  (``someone:[Text]``), and they would overwrite each other's cursor. The server
  marks them with ``origin_feed_name``, and they are skipped.
* Two conversations with the same name answer "Multiple matches". That is one
  step short, not unreachable: ``search_contact`` gives the candidates, and the
  one that is a conversation of exactly that name is used by its reference.
* A source that stays unreachable is said once, again when the error changes,
  and then every six hours with how long it has lasted — never every round.
* A high-volume conversation named in ``batch_feeds`` is held until its batch
  is due. Its cursor does not move meanwhile, so nothing is lost, only later.
"""

from __future__ import annotations

import time
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from airlock.extras.watch.config import ChatSource
from airlock.extras.watch.mcp import McpClient, McpError

UNREACHABLE_RENOTE_SECONDS = 6 * 3600


@dataclass(frozen=True)
class Message:
    at: float
    who: str
    body: str


@dataclass
class ChatState:
    cursors: dict[str, float] = field(default_factory=dict)
    pending: dict[str, float] = field(default_factory=dict)
    unreachable: dict[str, dict[str, Any]] = field(default_factory=dict)


def when(iso: str) -> float:
    """Server timestamps are UTC ISO strings. Compared only with unix cursors, never with local wall time."""
    text = (iso or "").strip().replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return 0.0
    return (moment if moment.tzinfo else moment.replace(tzinfo=UTC)).timestamp()


def is_fragment(text: str) -> bool:
    """One character, or no letter and no digit at all: an emoji or a stray mark, not a sentence.

    "Not urgent, let me look" passes, and that is right: whether it matters is
    judgement, not shape. Shape is decided here; judgement is the model's.
    """
    stripped = (text or "").strip()
    if len(stripped) <= 1:
        return True
    return not any(unicodedata.category(c)[0] in ("L", "N") for c in stripped)


def pick_ref(candidates: list[dict[str, Any]], name: str) -> str:
    """The reference of the one conversation (or, failing that, contact) named exactly ``name``; "" if not one."""
    for kind in ("feed", "contact"):
        exact = [
            c
            for c in candidates
            if c.get("ret_type") == kind and str(c.get("name") or "") == name and c.get("opaque_ref")
        ]
        if len(exact) == 1:
            return str(exact[0]["opaque_ref"])
        if len(exact) > 1:
            return ""
    return ""


def records(client: McpClient, name: str, args: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        return list((client.call("search_chat_records", **args) or {}).get("messages") or [])
    except McpError as exc:
        if "Multiple matches" not in str(exc):
            raise
        found = client.call("search_contact", name=name, response_locale="en") or {}
        candidates = found.get("candidates") or []
        ref = pick_ref(candidates, name)
        if not ref:
            raise McpError(f"{name!r} is ambiguous and none of {len(candidates)} candidates is exactly it") from exc
        retry = {k: v for k, v in args.items() if k not in ("contact_name", "search_group")}
        return list((client.call("search_chat_records", opaque_ref=ref, **retry) or {}).get("messages") or [])


def list_feeds(client: McpClient, source: ChatSource) -> list[dict[str, Any]]:
    feeds = (client.call("list_folder_feeds", all_chats=True, limit=source.feed_limit) or {}).get("feeds") or []
    return [
        f
        for f in feeds
        if str(f.get("name") or "").strip()
        and str(f.get("name")).strip() not in source.exclude
        and not (source.skip_threads and f.get("origin_feed_name"))
    ]


def baseline(client: McpClient, source: ChatSource) -> dict[str, float]:
    """The first round only: every conversation's latest message becomes its cursor, and nothing is reported."""
    return {str(f["name"]).strip(): when(str(f.get("last_message_send_at") or "")) for f in list_feeds(client, source)}


def _unreachable(state: ChatState, name: str, error: str, now: float, notes: list[str], handed: set[str]) -> None:
    before = state.unreachable.get(name) or {}
    rounds = int(before.get("rounds") or 0) + 1
    since = float(before.get("since") or now)
    renote = (
        not before
        or before.get("err") != error[:160]
        or now - float(before.get("noted_at") or 0) >= UNREACHABLE_RENOTE_SECONDS
    )
    state.unreachable[name] = {
        "since": since,
        "rounds": rounds,
        "err": error[:160],
        "noted_at": now if renote else float(before.get("noted_at") or now),
    }
    if renote:
        lasting = f"，自 {time.strftime('%m-%d %H:%M', time.localtime(since))} 起第 {rounds} 轮" if before else ""
        notes.append(f"{name} 取不到：{error}（游标未推进，下轮重查{lasting}）")
        handed.add(name)  # named in the digest, so a signal about it names something the scan offered


def scan_chat(
    client: McpClient, source: ChatSource, state: ChatState, now: float, notes: list[str], handed: set[str]
) -> list[tuple[str, list[Message]]]:
    """New messages per conversation, newest first. Moves each cursor it read past."""
    try:
        feeds = list_feeds(client, source)
    except McpError as exc:
        notes.append(f"会话列表取不到：{exc}（这一轮完全没看聊天）")
        return []
    found: list[tuple[str, list[Message]]] = []
    for feed in feeds:
        name = str(feed["name"]).strip()
        latest = when(str(feed.get("last_message_send_at") or ""))
        base = float(state.cursors.get(name) or 0)
        if not latest or latest <= base:
            continue
        if name in source.batch_feeds:
            first_seen = float(state.pending.get(name) or 0)
            if not first_seen:
                state.pending[name] = now
                continue
            if now - first_seen < source.batch_minutes * 60:
                continue
        args: dict[str, Any] = {
            "contact_name": name,
            "from_time": str(int(base) + 1),
            "to_time": str(int(now)),
            "limit": source.per_chat,
        }
        if feed.get("chat_type_label") == "group chat":
            args["search_group"] = True
        try:
            got = records(client, name, args)
        except McpError as exc:
            _unreachable(state, name, str(exc), now, notes, handed)
            continue
        picked: list[Message] = []
        for item in got:
            at = when(str(item.get("send_at") or ""))
            if at <= base:
                continue
            who = str(item.get("send_name") or "").strip()
            body = str(item.get("content") or "").strip()
            if (source.me and who == source.me) or any(bot in who for bot in source.bots):
                continue
            if not body:
                kind = str(item.get("message_type") or "").strip()
                body = f"[{kind or '非文字消息'}]" if kind != "text/plain text" else ""
            if is_fragment(body):
                continue
            picked.append(Message(at, who, body))
        picked.sort(key=lambda m: m.at, reverse=True)
        state.cursors[name] = latest
        state.unreachable.pop(name, None)
        state.pending.pop(name, None)
        if len(got) >= source.per_chat:
            notes.append(f"{name}：一次取满 {source.per_chat} 条，更早的可能没取到（游标照常推进到最新）")
        if picked:
            found.append((name, picked))
    return found
