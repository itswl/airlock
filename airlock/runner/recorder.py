"""A run's own record: one JSON line per event, each carrying the hash of the one before.

Written by the executor and the tool hooks, never by the agent's tools (the gate
refuses writes to it). The launcher verifies the chain before it accepts a
result, and the control plane stores the head in the ledger, so a record edited
after the fact no longer matches what was reported at the time.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from airlock.crypto import canonical_json, sha256_hex

SEED = "0" * 64


def line_hash(line: dict[str, Any]) -> str:
    return sha256_hex(canonical_json({key: value for key, value in line.items() if key != "hash"}))


class Recorder:
    """Appends to ``path`` (resuming its chain), hands each line to ``sink``, or both.

    The executor inside a worker container uses only a sink: its lines go out on
    stdout as they are written, and the launcher keeps them on the far side of
    the container boundary, so the record does not live where its subject runs.
    """

    def __init__(self, path: Path | None = None, *, sink: Callable[[str], None] | None = None) -> None:
        self.path = path
        self.sink = sink
        self._seq, self._prev = 0, SEED
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                for raw in path.read_text(encoding="utf-8").splitlines():
                    if raw.strip():
                        last = json.loads(raw)
                        self._seq, self._prev = int(last["seq"]), str(last["hash"])

    @property
    def head(self) -> str:
        return self._prev

    def write(self, kind: str, **data: Any) -> dict[str, Any]:
        self._seq += 1
        line: dict[str, Any] = {"seq": self._seq, "ts": round(time.time(), 6), "kind": kind, "data": data}
        line["prev"] = self._prev
        line["hash"] = line_hash(line)
        text = json.dumps(line, ensure_ascii=False, sort_keys=True)
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(text + "\n")
        if self.sink is not None:
            self.sink(text)
        self._prev = line["hash"]
        return line


def verify_lines(lines: list[dict[str, Any]]) -> dict[str, Any]:
    previous, checked = SEED, 0
    for line in lines:
        if line.get("prev") != previous or line_hash(line) != line.get("hash"):
            return {"intact": False, "checked": checked, "broken_at": line.get("seq"), "head": previous}
        previous, checked = str(line["hash"]), checked + 1
    return {"intact": True, "checked": checked, "broken_at": None, "head": previous}


def read_lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(raw) for raw in path.read_text(encoding="utf-8").splitlines() if raw.strip()]
