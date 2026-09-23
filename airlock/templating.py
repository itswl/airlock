"""Dotted-path lookup, ``{brace}`` rendering and ``when`` matching over untrusted payloads.

Rendering never raises: inbound payloads are other people's data, and an intake
that 500s on a surprise shape drops the event entirely. A missing path renders
as an empty string, and ``{a|b}`` takes the first path that yields something.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")


def resolve(data: Any, path: str) -> Any:
    current = data
    for token in path.split("."):
        if isinstance(current, list):
            try:
                current = current[int(token)]
            except (ValueError, IndexError):
                return None
        elif isinstance(current, Mapping):
            if token not in current:
                return None
            current = current[token]
        else:
            return None
    return current


def render(template: str, payload: Any) -> str:
    def substitute(match: re.Match[str]) -> str:
        for path in match.group(1).split("|"):
            value = resolve(payload, path.strip())
            if value is None or value == "":
                continue
            if isinstance(value, dict | list):
                return json.dumps(value, ensure_ascii=False)
            return str(value)
        return ""

    return _PLACEHOLDER.sub(substitute, template).strip()


def matches(when: Mapping[str, Any] | None, context: Any) -> bool:
    """True when every condition holds. An absent or empty ``when`` matches everything.

    ``key: value``       equal, or a member when the payload holds a list
    ``key: [a, b]``      the payload value is one of these
    ``key: {contains: x}`` / ``{regex: p}`` / ``{exists: bool}``
    """
    if not when:
        return True
    for path, expected in when.items():
        actual = resolve(context, path)
        if not _holds(expected, actual):
            return False
    return True


def _holds(expected: Any, actual: Any) -> bool:
    if isinstance(expected, Mapping):
        if "exists" in expected:
            return (actual is not None) == bool(expected["exists"])
        if actual is None:
            return False
        text = actual if isinstance(actual, str) else json.dumps(actual, ensure_ascii=False)
        if "contains" in expected:
            return str(expected["contains"]) in text
        if "regex" in expected:
            return re.search(str(expected["regex"]), text) is not None
        return False
    if isinstance(expected, list):
        if isinstance(actual, list):
            return any(str(item) in {str(e) for e in expected} for item in actual)
        return actual is not None and str(actual) in {str(e) for e in expected}
    if isinstance(actual, list):
        return str(expected) in {str(item) for item in actual}
    return actual is not None and str(actual) == str(expected)
