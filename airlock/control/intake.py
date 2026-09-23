"""The pipe's intake: verify, parse, filter, normalize. No content judgement beyond the rules you wrote.

Each source says how it proves itself (``verify``), which of its events become
work (``accept``) and how its payload maps onto one signal shape (``map``). An
event that fails verification is refused and recorded; one that no accept rule
matches is recorded as filtered and goes no further. Nothing here calls a model:
deciding what is worth waking an investigator for is procedure, and procedure in
code costs nothing on a quiet day.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from airlock.config import ControlConfig, Source
from airlock.crypto import (
    SignatureError,
    canonical_json,
    header,
    sha256_hex,
    verify,
    verify_bearer,
    verify_hub_signature,
)
from airlock.templating import matches, render

MAX_BODY_BYTES = 1_048_576


def verify_source(source: Source, headers: Mapping[str, str], body: bytes, *, now: float | None = None) -> None:
    if source.verify == "github":
        verify_hub_signature(source.secret, body, header(headers, "X-Hub-Signature-256"))
    elif source.verify == "hub-signature":
        verify_hub_signature(source.secret, body, header(headers, "X-Hub-Signature"))
    elif source.verify == "bearer":
        verify_bearer(source.secret, header(headers, "Authorization"))
    elif source.verify == "hmac":
        verify(source.secret, body, headers, now=now)
    else:  # pragma: no cover - config validation makes this unreachable
        raise SignatureError(f"unknown verification {source.verify!r}")


def parse(body: bytes) -> dict[str, Any]:
    if len(body) > MAX_BODY_BYTES:
        raise ValueError("body is larger than 1 MiB")
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("the body must be a JSON object")
    return data


def context(source: Source, headers: Mapping[str, str], payload: Mapping[str, Any]) -> dict[str, Any]:
    """What accept rules and templates see: the payload, plus ``event`` and ``source``."""
    event = header(headers, source.event_header) if source.event_header else str(payload.get("event") or "")
    return {**payload, "event": event, "source": source.name}


def accepted(source: Source, ctx: Mapping[str, Any]) -> bool:
    return any(matches(rule, ctx) for rule in source.accept)


def normalize(source: Source, ctx: Mapping[str, Any]) -> dict[str, Any]:
    t = source.templates
    title = render(t.get("title", "{title}"), ctx) or f"{source.name} event"
    key = render(t.get("key", ""), ctx) or sha256_hex(canonical_json(dict(ctx)))[:24]
    return {
        "source": source.name,
        "event": str(ctx.get("event") or ""),
        "title": title[:300],
        "body": render(t.get("body", "{body}"), ctx)[:20000],
        "url": render(t.get("url", "{url}"), ctx)[:1000],
        "key": key[:300],
        "labels": list(source.labels),
    }


def route(config: ControlConfig, signal: Mapping[str, Any]) -> str | None:
    for candidate in config.routes:
        if matches(candidate.when, signal):
            return candidate.investigator
    return None
