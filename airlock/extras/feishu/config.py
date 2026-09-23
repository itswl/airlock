"""The adapter's settings: one YAML file; secrets and ids by environment variable name."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from airlock.extras.settings import SettingsError, listing, value


@dataclass(frozen=True)
class FeishuConfig:
    name: str  # the adapter's name in airlock's config: /v1/adapters/<name>/...
    brand: str
    app_id: str
    app_secret: str
    webhook_url: str
    webhook_secret: str
    plans_chat: str
    notices_chat: str
    subscription_secret: str  # airlock's outlet signs with this
    notice_secret: str  # the watcher signs its notes with this
    people: frozenset[str]  # platform user ids that may speak through this adapter
    adapter_url: str
    adapter_secret: str
    intake_url: str
    intake_secret: str
    console_url: str
    state: Path


def load_feishu(source: str | Path | Mapping[str, Any], env: Mapping[str, str] | None = None) -> FeishuConfig:
    env = os.environ if env is None else env
    data = source if isinstance(source, Mapping) else yaml.safe_load(Path(source).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise SettingsError("the adapter configuration is a mapping")
    app_id = value(data, "app_id", env, "feishu")
    webhook = value(data, "webhook_url", env, "feishu")
    if bool(app_id) == bool(webhook):
        raise SettingsError("feishu: give app_id and app_secret (the application), or webhook_url, not both")
    airlock = data.get("airlock") or {}
    config = FeishuConfig(
        name=str(data.get("name") or "feishu"),
        brand=str(data.get("brand") or "feishu"),
        app_id=app_id,
        app_secret=value(data, "app_secret", env, "feishu", required=bool(app_id)),
        webhook_url=webhook,
        webhook_secret=value(data, "webhook_secret", env, "feishu"),
        plans_chat=value(data, "plans_chat", env, "feishu", required=bool(app_id)),
        notices_chat=value(data, "notices_chat", env, "feishu") or value(data, "plans_chat", env, "feishu"),
        subscription_secret=value(data, "subscription_secret", env, "feishu", required=True),
        notice_secret=value(data, "notice_secret", env, "feishu"),
        people=frozenset(listing(data, "people", env, "feishu")),
        adapter_url=str(airlock.get("adapter_url") or "").rstrip("/"),
        adapter_secret=value(airlock, "adapter_secret", env, "feishu.airlock"),
        intake_url=str(airlock.get("intake_url") or ""),
        intake_secret=value(airlock, "intake_secret", env, "feishu.airlock"),
        console_url=str(airlock.get("console_url") or "").rstrip("/"),
        state=Path(str(data.get("state") or "feishu.db")),
    )
    if config.brand not in ("feishu", "lark"):
        raise SettingsError("feishu: brand is feishu or lark")
    if config.adapter_url and not config.adapter_secret:
        raise SettingsError("feishu.airlock: adapter_url needs adapter_secret_env")
    if config.intake_url and not config.intake_secret:
        raise SettingsError("feishu.airlock: intake_url needs intake_secret_env")
    return config
