"""One round's scan: the window, the sources, the digest the judge reads, and the state they leave behind.

Output is the contract. Nothing new is ``None``, and the round is skipped: no
event, no model, no bill. Something new is a digest. A source that could not
be read counts as something, because an unreachable source is not a quiet one.

``offered`` is every subject handed to the judge in this round: each
conversation that had messages, each one named as unreachable, each Jira key.
Delivery accepts a signal only when its subject is one of them, so a round
cannot report a conversation that nothing surfaced. That was an after-the-fact
check before; here it is impossible by construction.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from airlock.extras.watch.chat import ChatState, Message, baseline, scan_chat
from airlock.extras.watch.config import Schedule, WatchConfig
from airlock.extras.watch.jira import Fetch, scan_jira
from airlock.extras.watch.mcp import McpClient, McpError

JIRA_KEY = re.compile(r"^([A-Z][A-Z0-9]+-\d+) \[", re.M)


def _minutes(hhmm: str) -> int:
    hours, _, minutes = hhmm.strip().partition(":")
    return int(hours) * 60 + int(minutes or 0)


def in_window(schedule: Schedule, now: float) -> bool:
    """The working hours, in the process's zone (the schedule's ``tz`` is applied at start)."""
    t = time.localtime(now)
    lo, _, hi = schedule.window.partition("-")
    first, _, last = schedule.days.partition("-")
    if not int(first) <= t.tm_wday + 1 <= int(last or first):
        return False
    return _minutes(lo) <= t.tm_hour * 60 + t.tm_min <= _minutes(hi)


@dataclass
class Round:
    at: float
    digest: str
    offered: dict[str, float]
    notes: list[str] = field(default_factory=list)
    dropped: int = 0
    # The state this round leaves behind. Written only by Scanner.commit, once the
    # round has been judged: a round whose judge failed is read again next tick.
    saved: dict[str, Any] = field(default_factory=dict)


def _read(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_atomically(path: Path, data: dict[str, Any]) -> None:
    """Next round reads this as its baseline; a half-written file would make it start over."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, path)


def trim(found: list[tuple[str, list[Message]]], budget: int) -> tuple[list[tuple[str, list[Message]]], int]:
    """Cut to what fits, dropping the OLDEST messages across all conversations first.

    What is dropped is gone: the cursors have moved. In a weekend's backlog the
    messages that need an answer are the latest ones; keeping the cursors put
    instead would meet the same backlog next round and be refused again, forever.
    """
    flat = sorted(((m, name) for name, messages in found for m in messages), key=lambda x: x[0].at, reverse=True)
    kept: list[tuple[Message, str]] = []
    used = 0
    for message, name in flat:
        size = len(message.body.encode("utf-8")) + len(message.who.encode("utf-8")) + 24
        if used + size > budget:
            break
        kept.append((message, name))
        used += size
    by_name: dict[str, list[Message]] = {}
    for message, name in kept:
        by_name.setdefault(name, []).append(message)
    return [(name, by_name[name]) for name, _ in found if name in by_name], len(flat) - len(kept)


def render(found: list[tuple[str, list[Message]]], notes: list[str], jira: list[str]) -> str:
    out: list[str] = []
    if notes:
        out.append("## ⚠️ 原样上报，不要判断")
        out += [f"- {note}" for note in notes]
        out.append("")
    if found:
        out.append("## 新消息（已剔除碎片、表情、你自己的发言和机器人；每组最新在前）")
        for name, messages in found:
            out += ["", f"### {name}"]
            out += [f"- {time.strftime('%m-%d %H:%M', time.localtime(m.at))} {m.who}：{m.body[:400]}" for m in messages]
        out.append("")
    if jira:
        out += ["## Jira", *jira]
    return "\n".join(out).strip()


class Scanner:
    def __init__(
        self,
        config: WatchConfig,
        *,
        chat: McpClient | None = None,
        jira: Fetch | None = None,
        clock: Any = time.time,
    ) -> None:
        self.config = config
        self.chat = chat
        self.jira = jira
        self.clock = clock
        self.path = config.state_dir / "scan.json"

    def run(self, *, force: bool = False, persist: bool = True) -> Round | None:
        """The round's digest, or None when there is nothing new.

        Nothing new is saved at once (cursors of held batches, a first round's
        floor). A round with a digest is saved by ``commit`` after it has been
        judged. ``force`` ignores the working hours; ``persist=False`` saves
        nothing in either case (a dry run).
        """
        now = float(self.clock())
        if not force and not in_window(self.config.schedule, now):
            return None
        saved = _read(self.path)
        state = ChatState(
            cursors={k: float(v) for k, v in ((saved or {}).get("feeds") or {}).items()},
            pending={k: float(v) for k, v in ((saved or {}).get("pending") or {}).items()},
            unreachable=dict((saved or {}).get("unreachable") or {}),
        )
        jira_state: dict[str, Any] = dict((saved or {}).get("jira") or {})
        notes: list[str] = []
        handed: set[str] = set()
        jira_lines: list[str] = []
        if self.config.jira is not None and self.jira is not None:
            try:
                jira_lines = scan_jira(self.config.jira, jira_state, self.jira, now)
            except Exception as exc:  # noqa: BLE001 — an unreadable tracker is reported, never silent
                notes.append(f"Jira 取不到：{type(exc).__name__} {str(exc)[:200]}")
        found: list[tuple[str, list[Message]]] = []
        if self.config.chat is not None and self.chat is not None:
            if state.cursors:
                found = scan_chat(self.chat, self.config.chat, state, now, notes, handed)
            else:
                # The first round lays the floor: every conversation's latest message
                # becomes its cursor and nothing old is reported. Jira has its own first-round rule.
                try:
                    state.cursors = baseline(self.chat, self.config.chat)
                except McpError as exc:
                    notes.append(f"建立基线失败：{exc}")
        jira_text = "\n".join(jira_lines)
        offered = {
            **{name: state.cursors.get(name, now) for name in handed},
            **{key: now for key in JIRA_KEY.findall(jira_text)},
            **{name: state.cursors.get(name, now) for name, _ in found},
        }
        overhead = len(jira_text.encode("utf-8")) + sum(len(n.encode("utf-8")) + 4 for n in notes)
        found, dropped = trim(found, self.config.digest_max - overhead)
        if dropped:
            notes.append(f"摘要超预算，丢掉了 {dropped} 条较早的消息（保留最新的）；游标照常推进，它们不会再出现")
        saved = {
            "round_at": now,
            "feeds": state.cursors,
            "pending": state.pending,
            "unreachable": state.unreachable,
            "jira": jira_state,
            "offered": offered,
        }
        if not (found or notes or jira_lines):
            if persist:
                write_atomically(self.path, saved)
            return None
        return Round(
            at=now,
            digest=render(found, notes, jira_lines),
            offered=offered,
            notes=notes,
            dropped=dropped,
            saved=saved,
        )

    def commit(self, scan: Round) -> None:
        """The round was judged: its messages have been read, and the cursors move past them."""
        write_atomically(self.path, scan.saved)
