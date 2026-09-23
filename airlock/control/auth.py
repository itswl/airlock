"""Who is at the web console: one operator, a scrypt password hash, a signed session cookie.

There is one person who can approve, so there is one account. The password is
never stored, only its scrypt hash, and that arrives through the environment
like every other secret. A session is a signed cookie (HttpOnly, SameSite=Strict,
Secure behind https); every form that changes something also carries a token
derived from the session, so a page on another site cannot submit one for you.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from collections import deque

COOKIE = "airlock_session"
SESSION_SECONDS = 12 * 3600
_N, _R, _P = 2**14, 8, 1


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    if not password:
        raise ValueError("an empty password cannot be hashed")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    encode = base64.urlsafe_b64encode
    return f"scrypt${_N}${_R}${_P}${encode(salt).decode()}${encode(digest).decode()}"


def check_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.urlsafe_b64decode(digest)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=base64.urlsafe_b64decode(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def _mac(secret: str, text: str) -> str:
    return hmac.new(secret.encode("utf-8"), text.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session(secret: str, name: str, *, now: float | None = None, ttl: int = SESSION_SECONDS) -> str:
    expires = int((now if now is not None else time.time()) + ttl)
    body = f"{name}|{expires}|{secrets.token_hex(8)}"
    return f"{body}|{_mac(secret, body)}"


def read_session(secret: str, cookie: str | None, *, now: float | None = None) -> str | None:
    """The operator name in a valid, unexpired session cookie; None for anything else."""
    if not cookie or cookie.count("|") != 3:
        return None
    body, _, signature = cookie.rpartition("|")
    if not hmac.compare_digest(_mac(secret, body), signature):
        return None
    name, expires, _nonce = body.split("|")
    try:
        if int(expires) < (now if now is not None else time.time()):
            return None
    except ValueError:
        return None
    return name


def csrf_token(secret: str, cookie: str) -> str:
    return _mac(secret, f"csrf|{cookie}")


def check_csrf(secret: str, cookie: str | None, token: str | None) -> bool:
    return bool(cookie and token) and hmac.compare_digest(csrf_token(secret, str(cookie)), str(token))


class Throttle:
    """At most ``limit`` failed logins per ``window`` seconds from one address."""

    def __init__(self, limit: int = 5, window: float = 300.0) -> None:
        self.limit, self.window = limit, window
        self._failures: dict[str, deque[float]] = {}

    def blocked(self, who: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        seen = self._failures.get(who)
        while seen and seen[0] < now - self.window:
            seen.popleft()
        return bool(seen) and len(seen) >= self.limit

    def failed(self, who: str, now: float | None = None) -> None:
        self._failures.setdefault(who, deque()).append(now if now is not None else time.time())

    def succeeded(self, who: str) -> None:
        self._failures.pop(who, None)
