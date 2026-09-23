"""One decision per tool call, before the tool runs; and a scan of what came back.

The guard decides shell commands. This module decides every tool: shell commands
through the guard, writes through the protected-path check, MCP tools through a
closed allowlist. It is a pure function so the in-process hook and any spawned
hook give the same answer.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from airlock.runner.guard import READONLY, bash_deny_reason

WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
_WRITE_PATH_KEYS = ("file_path", "notebook_path", "path")

# The files that steer the next run, plus this runner's own record. A run that
# can edit its instructions turns one injected line into a permanent one; a
# record its subject can rewrite is not a record.
PROTECTED_NAMES = (".claude", "CLAUDE.md", "AGENTS.md", ".airlock", "audit.jsonl")

_REDIRECT = re.compile(r">>?\s*['\"]?([^\s'\"|;&>]+)")


def protected_paths(workdir: Path) -> tuple[Path, ...]:
    return tuple(_resolve(workdir / name) for name in PROTECTED_NAMES)


def _resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def _is_protected(raw: str, workdir: Path) -> bool:
    if not raw:
        return False
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = workdir / candidate
    candidate = _resolve(candidate)
    return any(candidate == root or root in candidate.parents for root in protected_paths(workdir))


def _shell_writes_protected(command: str, workdir: Path) -> str | None:
    """A redirect, tee, cp/mv/install/dd/truncate, or sed -i aimed at a protected path."""
    for segment in re.split(r"[|;&\n]+", command or ""):
        words = segment.split()
        candidates = list(_REDIRECT.findall(segment))
        if words:
            head = Path(words[0]).name
            writes = head in ("cp", "mv", "install", "dd", "truncate", "tee") or (
                head == "sed" and any(w.startswith("-i") or w == "--in-place" for w in words)
            )
            if writes:
                candidates += [w for w in words[1:] if not w.startswith("-")]
        for candidate in candidates:
            hit = candidate.strip("\"'")
            if hit and _is_protected(hit, workdir):
                return hit
    return None


def mcp_deny_reason(tool_name: str, allowed: frozenset[str]) -> str | None:
    if not tool_name.startswith("mcp__"):
        return None
    if tool_name in allowed:
        return None
    parts = tool_name.split("__")
    if len(parts) >= 3 and f"mcp__{parts[1]}__*" in allowed:
        return None
    return (
        f"{tool_name} refused: it is not on this profile's MCP allowlist. Mounting a server does not grant its tools."
    )


def deny_reason(
    tool_name: str,
    tool_input: Any,
    *,
    mode: str = READONLY,
    workdir: Path | None = None,
    mcp_allowed: frozenset[str] = frozenset(),
) -> tuple[str, str] | None:
    """``(guard, reason)`` when the call must be refused, else None."""
    name = str(tool_name or "")
    data = tool_input if isinstance(tool_input, dict) else {}
    if name == "Bash":
        command = str(data.get("command") or "")
        reason = bash_deny_reason(command, mode)
        if reason is not None:
            return ("bash", reason)
        if workdir is not None:
            hit = _shell_writes_protected(command, workdir)
            if hit is not None:
                return ("input", f"input guard: this command writes {hit}, which steers the next run or is its record")
    if name.startswith("mcp__"):
        reason = mcp_deny_reason(name, mcp_allowed)
        if reason is not None:
            return ("mcp", reason)
    if name in WRITE_TOOLS and workdir is not None:
        for key in _WRITE_PATH_KEYS:
            target = str(data.get(key) or "")
            if _is_protected(target, workdir):
                return (
                    "input",
                    f"input guard: {target} steers the next run or is its record, so it may not be written",
                )
    return None


# Shapes that are issued credentials and nothing else. Narrow on purpose: a
# guard that fires on the word "password" is a guard people learn to ignore.
SECRET_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private key",
        re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z ]+ )?PRIVATE KEY-----|$)"),
    ),
    ("aws access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("openai-style api key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("json web token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
)
SCAN_LIMIT = 262_144


def secret_kinds(text: str) -> list[str]:
    """Which kinds of credential appear in ``text``. Names the kind, never the value."""
    sample = (text or "")[:SCAN_LIMIT]
    return sorted({name for name, pattern in SECRET_SHAPES if pattern.search(sample)})


def redact(text: str) -> tuple[str, list[str]]:
    """``text`` with every credential-shaped span replaced, and the kinds that were found."""
    found: set[str] = set()
    result = text or ""
    for name, pattern in SECRET_SHAPES:
        if pattern.search(result):
            found.add(name)
            result = pattern.sub(f"[redacted {name}]", result)
    return result, sorted(found)


def refusal(reason: str) -> dict[str, Any]:
    """A PreToolUse denial in the shape Claude Code reads."""
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
