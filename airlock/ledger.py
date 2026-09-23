"""The ledger: append-only, and every entry carries the hash of the one before it.

An edit or a deletion after the fact breaks the chain at a point ``verify`` can
name. That does not stop somebody with write access to the file from rebuilding
a self-consistent chain; what makes that detectable is a copy of the head held
somewhere else, which is why the control plane publishes ``ledger.checkpoint``
events through the pipe's outlet after every run.
"""

from __future__ import annotations

import json
import time
from typing import Any

from airlock.crypto import canonical_json, sha256_hex
from airlock.db import Database

SEED = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger (
    seq INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    work_id TEXT,
    actor TEXT NOT NULL,
    data TEXT NOT NULL,
    prev TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ledger_work ON ledger(work_id, seq);
"""


def entry_hash(entry: dict[str, Any]) -> str:
    body = {key: entry[key] for key in ("seq", "ts", "kind", "work_id", "actor", "data", "prev")}
    return sha256_hex(canonical_json(body))


class Ledger:
    def __init__(self, db: Database) -> None:
        self.db = db
        db.script(SCHEMA)

    def append(
        self,
        kind: str,
        *,
        work_id: str | None = None,
        actor: str = "system",
        data: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        with self.db.transaction() as conn:
            last = conn.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
            entry: dict[str, Any] = {
                "seq": (last["seq"] + 1) if last else 1,
                "ts": round(now if now is not None else time.time(), 6),
                "kind": kind,
                "work_id": work_id,
                "actor": actor,
                "data": json.dumps(data or {}, sort_keys=True, ensure_ascii=False),
                "prev": last["hash"] if last else SEED,
            }
            entry["hash"] = entry_hash(entry)
            conn.execute(
                "INSERT INTO ledger (seq, ts, kind, work_id, actor, data, prev, hash) VALUES (?,?,?,?,?,?,?,?)",
                [entry[key] for key in ("seq", "ts", "kind", "work_id", "actor", "data", "prev", "hash")],
            )
        return entry

    def head(self) -> str:
        row = self.db.one("SELECT hash FROM ledger ORDER BY seq DESC LIMIT 1")
        return row["hash"] if row else SEED

    def entries(self, *, work_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if work_id is None:
            rows = self.db.all("SELECT * FROM ledger ORDER BY seq DESC LIMIT ?", [limit])
        else:
            rows = self.db.all("SELECT * FROM ledger WHERE work_id = ? ORDER BY seq ASC LIMIT ?", [work_id, limit])
        for row in rows:
            row["data"] = json.loads(row["data"])
        return rows

    def verify(self) -> dict[str, Any]:
        """Walk the whole chain. ``broken_at`` names the first entry that does not add up."""
        previous, checked = SEED, 0
        for row in self.db.all("SELECT * FROM ledger ORDER BY seq ASC"):
            if row["prev"] != previous or entry_hash(row) != row["hash"]:
                return {"intact": False, "checked": checked, "broken_at": row["seq"], "head": previous}
            previous, checked = row["hash"], checked + 1
        return {"intact": True, "checked": checked, "broken_at": None, "head": previous}
