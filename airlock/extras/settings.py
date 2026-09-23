"""Reading the extras' YAML settings: a value, or the environment variable ``<key>_env`` names.

Secrets, and names that belong to you or your organisation, stay out of files
anyone may read: write ``<key>_env: VARIABLE`` instead of ``<key>: value``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class SettingsError(ValueError):
    """A setting cannot be used as written. The message names it."""


def value(item: Mapping[str, Any], key: str, env: Mapping[str, str], where: str, *, required: bool = False) -> str:
    if f"{key}_env" in item:
        name = str(item[f"{key}_env"])
        found = env.get(name, "")
        if required and not found:
            raise SettingsError(f"{where}: {key}_env names {name}, which is unset or empty")
        return found
    found = str(item.get(key) or "")
    if required and not found:
        raise SettingsError(f"{where}: {key} (or {key}_env) is required")
    return found


def listing(item: Mapping[str, Any], key: str, env: Mapping[str, str], where: str) -> tuple[str, ...]:
    """A list, or a comma-separated variable."""
    if f"{key}_env" in item:
        raw = env.get(str(item[f"{key}_env"]), "")
        return tuple(part.strip() for part in raw.split(",") if part.strip())
    found = item.get(key) or []
    if not isinstance(found, list):
        raise SettingsError(f"{where}: {key} is a list")
    return tuple(str(v) for v in found)
