"""A ceiling on what one investigator node spends in a rolling window, and prices from tokens.

Signals arrive without anyone watching. A watcher's task opens a work item,
and the investigation that follows is paid for by nobody's click. So each node
may declare ``AIRLOCK_BUDGET_USD`` over ``AIRLOCK_BUDGET_WINDOW_HOURS`` (24 by
default). When the window's spend has reached it, the node refuses the next
investigation. The refusal reaches the work item as an error, where it can be
seen and retried once the window has rolled on. It is never a silent drop.

What a turn cost comes from its tokens and the declared rates
(``AIRLOCK_PRICE_{IN,OUT,CACHE_READ,CACHE_WRITE}_PER_1M``) when any rate is
set. The CLI's own figure is an estimate from its own price list. For a
gateway's model it was an order of magnitude off, and for a resumed session
it includes the earlier turns again. It is used only when no rates are
declared, and then it overstates, which is the safe direction for a ceiling.
Every charge is a line in ``spend.jsonl`` in the node's state directory.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PER_MILLION = 1_000_000


@dataclass(frozen=True)
class Rates:
    input: float | None = None
    output: float | None = None
    cache_read: float | None = None
    cache_write: float | None = None

    @property
    def declared(self) -> bool:
        return any(r is not None for r in (self.input, self.output, self.cache_read, self.cache_write))

    def price(self, usage: Mapping[str, Any] | None) -> float | None:
        if not self.declared or not usage:
            return None
        parts = (
            (usage.get("input_tokens"), self.input),
            (usage.get("output_tokens"), self.output),
            (usage.get("cache_read_input_tokens"), self.cache_read),
            (usage.get("cache_creation_input_tokens"), self.cache_write),
        )
        return round(sum(float(tokens or 0) * float(rate or 0) / PER_MILLION for tokens, rate in parts), 6)


def rates_from(env: Mapping[str, str]) -> Rates:
    def one(name: str) -> float | None:
        raw = env.get(f"AIRLOCK_PRICE_{name}_PER_1M", "")
        return float(raw) if raw.strip() else None

    return Rates(one("IN"), one("OUT"), one("CACHE_READ"), one("CACHE_WRITE"))


class Budget:
    def __init__(
        self,
        path: Path,
        *,
        limit_usd: float | None,
        window_hours: float = 24.0,
        rates: Rates | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path, self.limit, self.window = path, limit_usd, window_hours * 3600
        self.rates = rates or Rates()
        self.clock = clock

    def _lines(self) -> list[dict[str, Any]]:
        try:
            return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except (OSError, ValueError):
            return []

    def spent(self) -> float:
        since = self.clock() - self.window
        return round(sum(float(line.get("cost_usd") or 0) for line in self._lines() if line.get("at", 0) >= since), 6)

    def refusal(self) -> str | None:
        """Why the next investigation may not start, or None."""
        if self.limit is None:
            return None
        spent = self.spent()
        if spent < self.limit:
            return None
        hours = self.window / 3600
        return (
            f"budget: this node has spent ${spent:.2f} in the last {hours:g}h, its ceiling is ${self.limit:.2f}. "
            "Nothing ran. Once the window has rolled on, start it again from the console (新会话重查)."
        )

    def charge(self, what: str, cli_cost: float | None, usage: Mapping[str, Any] | None) -> tuple[float, str]:
        """Record one turn's cost; returns it and how it was priced ("rates" or "cli")."""
        priced = self.rates.price(usage)
        cost, by = (priced, "rates") if priced is not None else (float(cli_cost or 0), "cli")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"at": self.clock(), "what": what, "cost_usd": cost, "priced_by": by}) + "\n")
        return cost, by

    def status(self) -> dict[str, Any]:
        return {
            "limit_usd": self.limit,
            "window_hours": self.window / 3600,
            "spent_usd": self.spent(),
            "priced_by": "rates" if self.rates.declared else "cli",
        }
