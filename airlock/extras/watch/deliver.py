"""Where a round's signals go, signed by this process and never by the agent.

A ``task`` becomes a work item: it is posted to airlock's intake door for the
watcher's source, signed with that source's secret (the same timestamped HMAC
every airlock door checks). A ``note`` is only something to read: it goes to
the notice door, usually the chat adapter's, which turns it into a card, and
it buys nothing.

``key`` is what makes a repeat join the work item it repeats: the same subject
and the same title are the same thing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

from airlock.crypto import sha256_hex, sign
from airlock.extras.watch.config import Door, WatchConfig
from airlock.extras.watch.judge import Signal


@dataclass
class Delivery:
    title: str
    kind: str
    level: str
    door: str
    status: int | None
    ok: bool
    reason: str = ""


def body_of(signal: Signal, watcher: str, round_at: float) -> dict[str, Any]:
    return {
        "title": signal.title,
        "detail": signal.detail,
        "level": signal.level,
        "kind": signal.kind,
        "origin": signal.origin,
        "subject": signal.subject,
        "watcher": watcher,
        "round_at": round_at,
        "key": sha256_hex(f"{signal.subject}\n{signal.title}".encode())[:24],
    }


def _post(client: httpx.Client, door: Door, payload: dict[str, Any]) -> tuple[int | None, str]:
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode()
    headers = {**sign(door.secret, body), "Content-Type": "application/json"}
    try:
        response = client.post(door.url, content=body, headers=headers)
    except httpx.HTTPError as exc:
        return None, f"{type(exc).__name__}: {str(exc)[:160]}"
    return response.status_code, response.text[:300]


def _work_id(reply: str) -> str:
    try:
        answer = json.loads(reply)
    except ValueError:
        return ""
    return str(answer.get("work_id") or "") if isinstance(answer, dict) else ""


def deliver(
    config: WatchConfig, signals: list[Signal], round_at: float, *, client: httpx.Client | None = None
) -> list[Delivery]:
    """Each task to the intake door, then (with its work item's id) to the notice door too, so the
    notices chat shows every signal as it happens; each note to the notice door only."""
    http = client or httpx.Client(timeout=30.0)
    done: list[Delivery] = []
    try:
        for signal in signals:
            body = body_of(signal, config.name, round_at)
            if signal.kind == "task":
                status, reply = _post(http, config.tasks, body)
                ok = status is not None and 200 <= status < 300
                done.append(Delivery(signal.title, signal.kind, signal.level, "tasks", status, ok, "" if ok else reply))
                if not ok or config.notes is None:
                    continue
                body["work_id"] = _work_id(reply)
            if config.notes is None:
                done.append(Delivery(signal.title, signal.kind, signal.level, "notes", None, False, "no notes door"))
                continue
            status, reply = _post(http, config.notes, body)
            ok = status is not None and 200 <= status < 300
            done.append(Delivery(signal.title, signal.kind, signal.level, "notes", status, ok, "" if ok else reply))
    finally:
        if client is None:
            http.close()
    return done
