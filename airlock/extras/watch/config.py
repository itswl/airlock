"""The watcher's settings: one YAML file. Secrets, and the names that are yours, come from the environment.

Every setting that is a secret, or that names somebody or something inside
your organisation (your display name, the bots in your chats, the chat
platform's own tool prefix, the conversations you batch), may be given as
``<key>_env: VARIABLE`` instead of ``<key>: value``. The file can then be read
by anyone without telling them who you are or where you work.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from airlock.extras.settings import SettingsError, listing, value

# One kind of error for every extra's settings; the message says which setting.
WatchConfigError = SettingsError


@dataclass(frozen=True)
class Schedule:
    every_minutes: int = 20
    window: str = "09:30-19:30"
    days: str = "1-5"
    tz: str = ""


@dataclass(frozen=True)
class ChatSource:
    url: str
    token: str = ""
    tool_prefix: str = ""
    me: str = ""
    bots: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    batch_feeds: tuple[str, ...] = ()
    batch_minutes: int = 60
    per_chat: int = 60
    feed_limit: int = 100
    skip_threads: bool = True
    timeout_seconds: float = 60.0


@dataclass(frozen=True)
class JiraSource:
    site: str
    email: str
    token: str
    project: str
    mention: str = ""
    lookback_minutes: int = 40
    tz: str = ""  # the Jira account's own zone: JQL dates are read in it (empty: this process's zone)


@dataclass(frozen=True)
class Door:
    url: str
    secret: str


@dataclass(frozen=True)
class Judge:
    model: str | None = None
    mcp_config: Path | None = None
    mcp_allowed: frozenset[str] = frozenset()
    max_budget_usd: float = 0.5
    timeout_seconds: float = 600.0
    max_turns: int = 20


@dataclass(frozen=True)
class WatchConfig:
    name: str
    state_dir: Path
    brief_file: Path
    schedule: Schedule
    chat: ChatSource | None
    jira: JiraSource | None
    tasks: Door
    notes: Door | None
    judge: Judge
    digest_max: int = 11000


def _door(item: Any, env: Mapping[str, str], where: str) -> Door:
    if not isinstance(item, Mapping) or not item.get("url"):
        raise WatchConfigError(f"{where}: needs a url and a secret_env")
    url = str(item["url"])
    if not url.startswith(("http://", "https://")):
        raise WatchConfigError(f"{where}: url must be http(s)")
    return Door(url=url, secret=value(item, "secret", env, where, required=True))


def load_watch(source: str | Path | Mapping[str, Any], env: Mapping[str, str] | None = None) -> WatchConfig:
    env = os.environ if env is None else env
    data = source if isinstance(source, Mapping) else yaml.safe_load(Path(source).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise WatchConfigError("the watch configuration is a mapping")
    schedule_raw = data.get("schedule") or {}
    schedule = Schedule(
        every_minutes=int(schedule_raw.get("every_minutes") or 20),
        window=str(schedule_raw.get("window") or "09:30-19:30"),
        days=str(schedule_raw.get("days") or "1-5"),
        tz=str(schedule_raw.get("tz") or ""),
    )
    if not 1 <= schedule.every_minutes <= 1440:
        raise WatchConfigError("schedule.every_minutes is between 1 and 1440")
    chat = None
    if data.get("chat"):
        raw = data["chat"]
        chat = ChatSource(
            url=value(raw, "url", env, "chat", required=True),
            token=value(raw, "token", env, "chat"),
            tool_prefix=value(raw, "tool_prefix", env, "chat"),
            me=value(raw, "me", env, "chat"),
            bots=listing(raw, "bots", env, "chat"),
            exclude=listing(raw, "exclude", env, "chat"),
            batch_feeds=listing(raw, "batch_feeds", env, "chat"),
            batch_minutes=int(raw.get("batch_minutes") or 60),
            per_chat=int(raw.get("per_chat") or 60),
            feed_limit=int(raw.get("feed_limit") or 100),
            skip_threads=bool(raw.get("skip_threads", True)),
            timeout_seconds=float(raw.get("timeout_seconds") or 60),
        )
    jira = None
    if data.get("jira"):
        raw = data["jira"]
        jira = JiraSource(
            site=value(raw, "site", env, "jira", required=True).rstrip("/"),
            email=value(raw, "email", env, "jira", required=True),
            token=value(raw, "token", env, "jira", required=True),
            project=value(raw, "project", env, "jira", required=True),
            mention=value(raw, "mention", env, "jira"),
            lookback_minutes=int(raw.get("lookback_minutes") or 40),
            tz=str(raw.get("tz") or ""),
        )
    if chat is None and jira is None:
        raise WatchConfigError("nothing to watch: configure chat, jira, or both")
    judge_raw = data.get("judge") or {}
    allowed = judge_raw.get("mcp_allowed") or []
    judge = Judge(
        model=str(judge_raw.get("model") or env.get("AIRLOCK_MODEL") or "") or None,
        mcp_config=Path(judge_raw["mcp_config"]) if judge_raw.get("mcp_config") else None,
        mcp_allowed=frozenset(str(a) for a in (allowed if isinstance(allowed, list) else str(allowed).split(","))),
        max_budget_usd=float(judge_raw.get("max_budget_usd") or 0.5),
        timeout_seconds=float(judge_raw.get("timeout_seconds") or 600),
        max_turns=int(judge_raw.get("max_turns") or 20),
    )
    brief = Path(str(data.get("brief_file") or ""))
    if not str(brief) or not brief.is_file():
        raise WatchConfigError(f"brief_file {brief} is not a readable file")
    return WatchConfig(
        name=str(data.get("name") or "watch"),
        state_dir=Path(str(data.get("state_dir") or "state")),
        brief_file=brief,
        schedule=schedule,
        chat=chat,
        jira=jira,
        tasks=_door(data.get("tasks"), env, "tasks"),
        notes=_door(data["notes"], env, "notes") if data.get("notes") else None,
        judge=judge,
        digest_max=int(data.get("digest_max") or 11000),
    )
