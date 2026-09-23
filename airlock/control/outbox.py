"""The pipe's outlet: every notification is a signed webhook, retried, and finally dead-lettered.

Adapters for chat and mail subscribe here like any other receiver; nothing in the
control plane knows what a Feishu card or a Slack block looks like. A delivery
that keeps failing is retried with backoff and then marked dead, with the last
error kept, so a notification that never arrived is a row somebody can read.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx

from airlock.config import Subscription
from airlock.crypto import canonical_json, sign
from airlock.db import Database

logger = logging.getLogger("airlock.outbox")

BACKOFF_SECONDS = (30, 60, 120, 240, 480, 600, 600, 600)
MAX_ATTEMPTS = len(BACKOFF_SECONDS)


class Outbox:
    def __init__(self, db: Database, subscriptions: tuple[Subscription, ...]) -> None:
        self.db = db
        self.subscriptions = {s.name: s for s in subscriptions}

    def enqueue(self, event: str, payload: dict[str, Any], *, now: float | None = None) -> int:
        at = now if now is not None else time.time()
        count = 0
        for subscription in self.subscriptions.values():
            if subscription.wants(event):
                self.db.execute(
                    "INSERT INTO outbox (created_at, subscription, event, payload, status, next_at) VALUES (?,?,?,?,?,?)",
                    [at, subscription.name, event, json.dumps(payload, ensure_ascii=False), "pending", at],
                )
                count += 1
        return count

    async def deliver_due(
        self, client: httpx.AsyncClient, *, now: float | None = None, limit: int = 50
    ) -> dict[str, int]:
        at = now if now is not None else time.time()
        counts = {"sent": 0, "retry": 0, "dead": 0}
        rows = self.db.all(
            "SELECT * FROM outbox WHERE status = 'pending' AND next_at <= ? ORDER BY id LIMIT ?", [at, limit]
        )
        for row in rows:
            subscription = self.subscriptions.get(row["subscription"])
            if subscription is None:
                self.db.execute(
                    "UPDATE outbox SET status='dead', last_error=? WHERE id=?", ["subscription removed", row["id"]]
                )
                counts["dead"] += 1
                continue
            body = canonical_json(
                {"id": row["id"], "event": row["event"], "at": row["created_at"], "payload": json.loads(row["payload"])}
            )
            headers = {
                **sign(subscription.secret, body, now=at),
                "Content-Type": "application/json",
                "X-Airlock-Event": row["event"],
            }
            error = ""
            try:
                response = await client.post(subscription.url, content=body, headers=headers, timeout=15)
                if 200 <= response.status_code < 300:
                    self.db.execute(
                        "UPDATE outbox SET status='sent', sent_at=?, attempts=attempts+1 WHERE id=?", [at, row["id"]]
                    )
                    counts["sent"] += 1
                    continue
                error = f"HTTP {response.status_code}"
            except httpx.HTTPError as exc:
                error = f"{type(exc).__name__}: {exc}"[:300]
            attempts = row["attempts"] + 1
            if attempts >= MAX_ATTEMPTS:
                self.db.execute(
                    "UPDATE outbox SET status='dead', attempts=?, last_error=? WHERE id=?", [attempts, error, row["id"]]
                )
                logger.warning(
                    "delivery %s to %s is dead after %s attempts: %s", row["id"], subscription.name, attempts, error
                )
                counts["dead"] += 1
            else:
                self.db.execute(
                    "UPDATE outbox SET attempts=?, next_at=?, last_error=? WHERE id=?",
                    [attempts, at + BACKOFF_SECONDS[attempts - 1], error, row["id"]],
                )
                counts["retry"] += 1
        return counts
