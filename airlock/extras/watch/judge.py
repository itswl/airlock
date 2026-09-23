"""The one part of a round that needs a model: what, of what the scan found, deserves you.

The model reads your brief, then the digest, and answers with a single fenced
``signals`` block. It has no built-in tools at all — no files, no shell — and
only the MCP tools the configuration names (the chat's read tools, through the
gateway), for when a line needs its context. So it cannot read the state
files, the brief's source, or this process's environment, and it cannot post
anything: posting is ``deliver.py``'s, after checking every signal.
"""

from __future__ import annotations

import json
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock.extras.watch.config import WatchConfig
from airlock.extras.watch.scan import Round
from airlock.runner.engine import Engine, EngineRequest, ToolPolicy
from airlock.runner.guard import READONLY

LEVELS = ("high", "low")
KINDS = ("task", "note")
CONTRACT = """
---

Answer with exactly one fenced block labelled `signals`: a JSON list, one object per thing worth
telling the operator, `[]` when nothing is. Each object has:

- `title`: one line, it becomes the card's title
- `detail`: the context — who said what, where
- `level`: `high` when the operator must handle or answer it personally; otherwise `low`
- `kind`: `task` when somebody asks the operator to do something; otherwise `note`
- `conversation`: the `###` heading it came from, copied exactly — or, for a Jira item or a ⚠️ line,
  `origin` instead: `Jira / <KEY>` or `scan / <what was unreachable>`

Everything outside that block is kept in the round's record and read by nobody.
"""
_BLOCK = re.compile(r"```signals\s*\n(.*?)\n```", re.S)


@dataclass
class Signal:
    title: str
    detail: str
    level: str
    kind: str
    origin: str
    subject: str


@dataclass
class Judgement:
    signals: list[Signal] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    text: str = ""
    error: str | None = None
    cost_usd: float | None = None
    usage: dict[str, int] | None = None


def prompt(config: WatchConfig, scan: Round) -> str:
    brief = config.brief_file.read_text(encoding="utf-8").strip()
    return f"{brief}\n\n---\n\n{scan.digest}\n{CONTRACT}"


def parse(text: str, offered: dict[str, float], origin_prefix: str) -> tuple[list[Signal], list[str]]:
    """The signals the model named, each checked against what the scan offered; the rest with why not."""
    match = _BLOCK.search(text or "")
    if match is None:
        return [], ["the answer has no ```signals block"]
    try:
        items = json.loads(match.group(1))
    except ValueError as exc:
        return [], [f"the signals block is not JSON: {exc}"]
    if not isinstance(items, list):
        return [], ["the signals block is not a list"]
    signals: list[Signal] = []
    dropped: list[str] = []
    for item in items:
        if not isinstance(item, dict) or not str(item.get("title") or "").strip():
            dropped.append(f"not a signal: {json.dumps(item, ensure_ascii=False)[:120]}")
            continue
        title = str(item["title"]).strip()[:200]
        level = str(item.get("level") or "low").lower()
        kind = str(item.get("kind") or "note").lower()
        conversation = str(item.get("conversation") or "").strip()
        origin = str(item.get("origin") or "").strip()
        if conversation:
            if conversation not in offered:
                dropped.append(f"{title!r} names conversation {conversation!r}, which this round did not offer")
                continue
            subject, origin = conversation, f"{origin_prefix} / {conversation}"
        elif origin.startswith("Jira / "):
            subject = origin[len("Jira / ") :].strip()
            if subject not in offered:
                dropped.append(f"{title!r} names {origin!r}, which this round did not offer")
                continue
        elif origin.startswith("scan / "):
            # A relayed ⚠️ line: never a paid investigation, whatever the model called it.
            subject, level, kind = origin, "low", "note"
        else:
            dropped.append(f"{title!r} names neither a conversation nor an origin")
            continue
        signals.append(
            Signal(
                title=title,
                detail=str(item.get("detail") or "").strip()[:4000],
                level=level if level in LEVELS else "low",
                kind=kind if kind in KINDS else "note",
                origin=origin,
                subject=subject,
            )
        )
    return signals, dropped


async def judge(
    config: WatchConfig,
    scan: Round,
    engine_factory: Callable[[], Engine],
    *,
    record: Callable[..., Any] | None = None,
) -> Judgement:
    with tempfile.TemporaryDirectory(prefix="airlock-watch-") as scratch:
        # An empty, throwaway working directory: the engine needs one, and there is nothing in it to read.
        policy = ToolPolicy(READONLY, Path(scratch), mcp_allowed=config.judge.mcp_allowed, record=record, confine=True)
        request = EngineRequest(
            prompt=prompt(config, scan),
            system="You are the watcher. You decide what, of what the scan found, deserves the operator. You never act.",
            mode=READONLY,
            workdir=Path(scratch),
            max_turns=config.judge.max_turns,
            timeout_seconds=config.judge.timeout_seconds,
        )
        try:
            result = await engine_factory().run(request, policy)
        except Exception as exc:  # noqa: BLE001 — a crashed engine is a failed round, with its reason
            return Judgement(error=f"{type(exc).__name__}: {exc}"[:500])
    judgement = Judgement(
        text=result.text, error=result.error, cost_usd=result.cost_usd, usage=dict(result.usage or {})
    )
    if result.error is None:
        judgement.signals, judgement.dropped = parse(result.text, scan.offered, "chat")
    return judgement


def default_engine(config: WatchConfig) -> Callable[[], Engine]:
    def make() -> Engine:
        from airlock.runner.claude_engine import ClaudeEngine

        # No built-in tools: the judge reads what it is given, and the chat through its MCP read tools.
        return ClaudeEngine(
            model=config.judge.model,
            tools=(),
            max_budget_usd=config.judge.max_budget_usd,
            mcp_config=config.judge.mcp_config,
        )

    return make


def summary(judgement: Judgement) -> dict[str, Any]:
    return {
        "signals": len(judgement.signals),
        "dropped": judgement.dropped,
        "error": judgement.error,
        "cost_usd": judgement.cost_usd,
        "usage": judgement.usage,
    }
