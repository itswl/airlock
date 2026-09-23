"""Signatures and hashes, in one place so every door checks them the same way.

Three shapes arrive at the pipe's intake and one shape is used everywhere else:

* ``sign`` / ``verify`` — this system's own timestamped HMAC. The signature covers
  ``"{timestamp}." + body``, so a captured request stops being accepted once the
  timestamp leaves the window. Every internal hop uses it: control plane to
  investigator and back, control plane to launcher and back, the outbound webhooks.
* ``verify_hub_signature`` — GitHub's ``X-Hub-Signature-256`` and Jira's
  ``X-Hub-Signature`` when a secret is set: ``sha256=`` + HMAC over the body.
* ``verify_bearer`` — a shared token, for senders that can only set a header.

Every comparison is constant-time, and an empty secret is refused rather than
treated as "no check": a variable that failed to load must fail closed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Mapping
from typing import Any

TS_HEADER = "X-Airlock-Timestamp"
SIG_HEADER = "X-Airlock-Signature"
PROFILE_HEADER = "X-Airlock-Profile"
MAX_SKEW_SECONDS = 300


class SignatureError(Exception):
    """The request is not provably from who it claims. The message says which check failed."""


def canonical_json(obj: Any) -> bytes:
    """One byte string per value, so a hash over it means the same thing everywhere."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mac(secret: str, message: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def header(headers: Mapping[str, str], name: str) -> str:
    """Case-insensitive lookup that works for plain dicts and for Starlette headers."""
    value = headers.get(name)
    if value is None:
        lowered = name.lower()
        for key, candidate in headers.items():
            if key.lower() == lowered:
                return candidate
        return ""
    return value


def sign(secret: str, body: bytes, *, now: float | None = None) -> dict[str, str]:
    if not secret:
        raise ValueError("refusing to sign with an empty secret")
    stamp = str(int(now if now is not None else time.time()))
    return {TS_HEADER: stamp, SIG_HEADER: "sha256=" + _mac(secret, stamp.encode() + b"." + body)}


def verify(
    secret: str,
    body: bytes,
    headers: Mapping[str, str],
    *,
    now: float | None = None,
    max_skew: int = MAX_SKEW_SECONDS,
) -> None:
    """Raise SignatureError unless ``body`` was signed with ``secret`` recently."""
    if not secret:
        raise SignatureError("no secret is configured for this door")
    stamp, signature = header(headers, TS_HEADER), header(headers, SIG_HEADER)
    if not stamp or not signature:
        raise SignatureError("missing signature headers")
    try:
        when = int(stamp)
    except ValueError as exc:
        raise SignatureError("unreadable timestamp") from exc
    current = now if now is not None else time.time()
    if abs(current - when) > max_skew:
        raise SignatureError("timestamp is outside the allowed window")
    expected = "sha256=" + _mac(secret, stamp.encode() + b"." + body)
    if not hmac.compare_digest(expected, signature):
        raise SignatureError("signature does not match")


def verify_hub_signature(secret: str, body: bytes, value: str) -> None:
    """GitHub ``X-Hub-Signature-256`` / Jira ``X-Hub-Signature``: ``sha256=<hex hmac of body>``."""
    if not secret:
        raise SignatureError("no secret is configured for this door")
    if not value or not value.startswith("sha256="):
        raise SignatureError("missing or non-sha256 hub signature")
    if not hmac.compare_digest("sha256=" + _mac(secret, body), value):
        raise SignatureError("hub signature does not match")


def verify_bearer(expected: str, authorization: str) -> None:
    if not expected:
        raise SignatureError("no token is configured for this door")
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise SignatureError("missing bearer token")
    if not hmac.compare_digest(expected.encode(), token.strip().encode()):
        raise SignatureError("bearer token does not match")
