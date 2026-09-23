"""Confinement for an agent that runs on a host instead of in its own container.

In a container, the filesystem an investigator can read is the one it was
given. On a laptop — the demo, the local runtime, a first try with a real
model — it is the whole machine: every credential file and every config that
names somebody. Whatever a tool reads goes to the model provider as tool
output. So when a node is not in a container it runs confined:

* only the tools named here exist; anything else is refused;
* file tools must name paths inside the working directory;
* the shell runs plain read commands only — no substitution, redirection,
  subshells or background jobs — and every path they name must be inside the
  working directory as well.

This is a narrow allowlist on purpose. It is not a sandbox in the kernel's
sense: a container is still the boundary for anything that matters, and this
exists so that trying airlock on a laptop does not hand the laptop to a model.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from airlock.runner.gate import PROTECTED_NAMES

CONSULT_TOOL = "mcp__airlock__consult"

# Tool name -> the arguments that name a path.
FILE_TOOLS: dict[str, tuple[str, ...]] = {
    "Read": ("file_path",),
    "Write": ("file_path",),
    "Edit": ("file_path",),
    "MultiEdit": ("file_path",),
    "NotebookEdit": ("notebook_path",),
    "Glob": ("path", "pattern"),
    "Grep": ("path",),
    "LS": ("path",),
}
CONFINED_TOOLS = ("Bash", "Read", "Write", "Edit", "Glob", "Grep", "TodoWrite")
# Skill loads instructions the operator put in .claude/skills; it reads nothing
# else. MCP tools are not listed: the MCP allowlist in the gate decides them.
ALLOWED = frozenset({*FILE_TOOLS, "Bash", "TodoWrite", "Skill", CONSULT_TOOL})

# Commands that only read. sed, awk, xargs, tee and every interpreter are
# absent: each can write files or run other programs from inside its argument.
READ_COMMANDS = frozenset(
    {
        "cat",
        "head",
        "tail",
        "grep",
        "egrep",
        "fgrep",
        "wc",
        "ls",
        "find",
        "sort",
        "uniq",
        "cut",
        "tr",
        "diff",
        "jq",
        "nl",
        "column",
        "stat",
        "file",
        "basename",
        "dirname",
        "echo",
        "pwd",
        "date",
    }
)
FIND_ACTIONS = frozenset({"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"})


def inside(root: Path, raw: str) -> bool:
    """Whether ``raw`` (relative to ``root`` unless absolute) resolves inside ``root``, symlinks followed."""
    if raw.startswith("~"):
        return False
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved, base = candidate.resolve(), root.resolve()
    except OSError:
        return False
    return resolved == base or base in resolved.parents


def _protected(root: Path, raw: str) -> bool:
    target = Path(raw) if Path(raw).is_absolute() else root / raw
    try:
        target = target.resolve()
    except OSError:
        return True
    guarded = [(root / name).resolve() for name in PROTECTED_NAMES]
    return any(target == g or g in target.parents for g in guarded)


def _unquoted_hazard(command: str) -> str | None:
    """The first shell feature outside single quotes that could run or write something."""
    quote = ""
    for index, char in enumerate(command):
        if quote == "'":
            if char == "'":
                quote = ""
            continue
        if char == "\\":
            return "a backslash escape"
        if quote == '"':
            if char == '"':
                quote = ""
            elif char in "$`":
                return "expansion inside double quotes"
            continue
        if char in "'\"":
            quote = char
        elif char in "$`":
            return "command or variable substitution"
        elif char in "<>":
            return "redirection"
        elif char in "()":
            return "a subshell"
        elif char == "&" and command[index : index + 2] != "&&" and command[index - 1 : index + 1] != "&&":
            return "a background job"
        elif char == "\n":
            return "more than one line"
    return "an unclosed quote" if quote else None


def _segments(command: str) -> list[str]:
    """Split on | || && ; outside quotes."""
    parts, current, quote, i = [], [], "", 0
    while i < len(command):
        char = command[i]
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
            current.append(char)
        elif command.startswith(("||", "&&"), i):
            parts.append("".join(current))
            current, i = [], i + 2
            continue
        elif char in "|;":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    parts.append("".join(current))
    return [p for p in (s.strip() for s in parts) if p]


def shell_reason(command: str, root: Path) -> str | None:
    hazard = _unquoted_hazard(command)
    if hazard is not None:
        return f"only plain read commands run here, and this uses {hazard}"
    for segment in _segments(command):
        try:
            words = shlex.split(segment)
        except ValueError:
            return "the command could not be parsed"
        if not words:
            continue
        head = os.path.basename(words[0])
        if head not in READ_COMMANDS:
            return f"{head} is not one of the read commands available here: {', '.join(sorted(READ_COMMANDS))}"
        if head == "find" and any(w in FIND_ACTIONS for w in words):
            return "find may search here, not act on what it finds"
        if head == "sort" and any(w == "-o" or w.startswith(("-o", "--output")) for w in words[1:]):
            return "sort may not write a file"
        # Every operand and every option value is checked as if it were a path —
        # including a grep pattern, because `grep -f FILE` makes the first
        # operand a file. A pattern that starts with / is refused; drop the slash.
        operands: list[str] = []
        for word in words[1:]:
            if word.startswith("-"):
                _, _, value = word.partition("=")
                if value:
                    operands.append(value)
                continue
            operands.append(word)
        if head == "uniq" and len(operands) > 1:
            return "uniq may not write a file"
        for word in operands:
            pathish = word.startswith(("/", "~", ".")) or "/" in word
            if pathish and not inside(root, word):
                return (
                    f"{word} is outside this investigator's working directory "
                    "(every argument is read as a path; a pattern must not start with / or ~)"
                )
            if pathish and _protected(root, word):
                return f"{word} is this node's own state or instructions"
    return None


def confine_reason(tool: str, tool_input: Mapping[str, Any], root: Path) -> str | None:
    """Why this call may not run on a confined node, or None."""
    if tool.startswith("mcp__"):
        return None
    if tool not in ALLOWED:
        return f"{tool} is not available to an investigator running outside a container"
    if tool in FILE_TOOLS:
        for key in FILE_TOOLS[tool]:
            value = str(tool_input.get(key) or "")
            if not value:
                continue
            if key == "pattern" and not value.startswith(("/", "~")) and ".." not in value:
                continue
            probe = (value.split("*", 1)[0] or ".") if key == "pattern" else value
            if not inside(root, probe):
                return f"{value} is outside this investigator's working directory"
        return None
    if tool == "Bash":
        return shell_reason(str(tool_input.get("command") or ""), root)
    return None
