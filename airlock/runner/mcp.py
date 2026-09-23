"""The MCP servers an investigator may use: one file, read fresh every run, and nothing else.

The operator names the servers in a JSON file in the ``.mcp.json`` shape,
``{"mcpServers": {"name": {...}}}``. It is read at the start of every run, so an
edit takes effect on the next run without a restart, and it is the only MCP
configuration the CLI sees (strict): nothing in anybody's settings adds a server.

A configured server does not grant its tools. Each tool the agent may call is
named in ``AIRLOCK_MCP_ALLOWED`` (``mcp__<server>__<tool>``, or a pattern inside
one server such as ``mcp__<server>__get_*``) and the gate refuses the rest.

What a server can reach is what its credentials can reach, and the agent runs
as the same user in the same container: it can read those credentials too. So
an investigator's MCP servers hold read-only credentials, for the same reason
its shell does. The tool allowlist is a second layer, not the boundary. A
server whose only credential can also write goes behind ``airlock.mcpgate``,
which holds the credential and forwards only the tools named for it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from airlock.runner.gate import PROTECTED_NAMES

RESERVED = frozenset({"airlock"})
KINDS = ("stdio", "http", "sse")


class McpConfigError(ValueError):
    """The MCP configuration cannot be used as written. The message says where."""


def load_mcp_servers(path: Path) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise McpConfigError(f"{path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise McpConfigError(f"{path}: not JSON ({exc})") from exc
    servers = data.get("mcpServers", data) if isinstance(data, dict) else None
    if not isinstance(servers, dict):
        raise McpConfigError(f'{path}: expected {{"mcpServers": {{"<name>": {{...}}}}}}')
    result: dict[str, dict[str, Any]] = {}
    for name, spec in servers.items():
        if name in RESERVED:
            raise McpConfigError(f"{path}: the server name {name!r} is airlock's own")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(name)):
            raise McpConfigError(f"{path}: server name {name!r} must be letters, digits, - or _")
        if not isinstance(spec, dict):
            raise McpConfigError(f"{path}: server {name} must be an object")
        kind = str(spec.get("type") or "stdio")
        if kind not in KINDS:
            raise McpConfigError(f"{path}: server {name} has type {kind!r}; use one of {', '.join(KINDS)}")
        if kind == "stdio" and not spec.get("command"):
            raise McpConfigError(f"{path}: server {name} needs a command")
        if kind != "stdio" and not spec.get("url"):
            raise McpConfigError(f"{path}: server {name} needs a url")
        result[str(name)] = dict(spec)
    return result


def safe_location(path: Path, workdir: Path) -> bool:
    """Outside the working directory, or inside a part of it the agent cannot write."""
    target, root = path.resolve(), workdir.resolve()
    if target != root and root not in target.parents:
        return True
    guarded = [(root / name).resolve() for name in PROTECTED_NAMES]
    return any(g in target.parents for g in guarded)
