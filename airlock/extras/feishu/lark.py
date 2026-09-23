"""Sending to Feishu / Lark: as the application (message API), or through a custom bot's webhook.

The application can send to any chat it was added to, reply inside a thread,
and gets a message id back, which is how a later reply is traced to its work
item. A custom bot can only post into its one chat: no id comes back, and
nothing can be threaded or answered. Both are here, and the difference is said
rather than papered over.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

import httpx

DOMAINS = {"feishu": "https://open.feishu.cn", "lark": "https://open.larksuite.com"}


class LarkError(RuntimeError):
    """The platform refused or could not be reached. The message carries its code."""


class Lark:
    def __init__(
        self,
        app_id: str,
        app_secret: str,
        *,
        brand: str = "feishu",
        transport: httpx.BaseTransport | None = None,
        clock: Any = time.time,
    ) -> None:
        if brand not in DOMAINS:
            raise ValueError(f"brand is one of {', '.join(DOMAINS)}")
        self.app_id, self.app_secret = app_id, app_secret
        self.http = httpx.Client(base_url=DOMAINS[brand], timeout=30.0, transport=transport)
        self.clock = clock
        self._token, self._expires = "", 0.0

    def _call(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = self.http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise LarkError(f"{type(exc).__name__}: {str(exc)[:160]}") from exc
        try:
            data = response.json()
        except ValueError as exc:
            raise LarkError(f"HTTP {response.status_code}: not JSON") from exc
        if response.status_code >= 400 or data.get("code", 0) != 0:
            raise LarkError(f"HTTP {response.status_code} code {data.get('code')}: {str(data.get('msg'))[:200]}")
        return data

    def token(self) -> str:
        if self._token and self.clock() < self._expires - 60:
            return self._token
        data = self._call(
            "POST",
            "/open-apis/auth/v3/tenant_access_token/internal",
            json={"app_id": self.app_id, "app_secret": self.app_secret},
        )
        self._token, self._expires = str(data["tenant_access_token"]), self.clock() + float(data.get("expire") or 0)
        return self._token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token()}"}

    def send(self, chat_id: str, card: dict[str, Any]) -> str:
        data = self._call(
            "POST",
            "/open-apis/im/v1/messages",
            params={"receive_id_type": "chat_id"},
            headers=self._headers(),
            json={"receive_id": chat_id, "msg_type": "interactive", "content": json.dumps(card, ensure_ascii=False)},
        )
        return str((data.get("data") or {}).get("message_id") or "")

    def reply(self, message_id: str, card: dict[str, Any]) -> str:
        data = self._call(
            "POST",
            f"/open-apis/im/v1/messages/{message_id}/reply",
            headers=self._headers(),
            json={"msg_type": "interactive", "content": json.dumps(card, ensure_ascii=False), "reply_in_thread": True},
        )
        return str((data.get("data") or {}).get("message_id") or "")


class Webhook:
    """A custom bot: one chat, send only. ``secret`` when the bot has signature checking on."""

    def __init__(
        self, url: str, secret: str = "", *, transport: httpx.BaseTransport | None = None, clock: Any = time.time
    ) -> None:
        self.url, self.secret, self.clock = url, secret, clock
        self.http = httpx.Client(timeout=30.0, transport=transport)

    def send(self, chat_id: str, card: dict[str, Any]) -> str:
        body: dict[str, Any] = {"msg_type": "interactive", "card": card}
        if self.secret:
            stamp = str(int(self.clock()))
            key = f"{stamp}\n{self.secret}".encode()
            body |= {"timestamp": stamp, "sign": base64.b64encode(hmac.new(key, b"", hashlib.sha256).digest()).decode()}
        try:
            response = self.http.post(self.url, json=body)
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise LarkError(f"webhook: {type(exc).__name__}: {str(exc)[:160]}") from exc
        if data.get("code", data.get("StatusCode", 0)) != 0:
            raise LarkError(f"webhook code {data.get('code')}: {str(data.get('msg'))[:200]}")
        return ""  # a custom bot's message has no id we are given

    def reply(self, message_id: str, card: dict[str, Any]) -> str:
        return self.send("", card)  # no threads for a custom bot: a new message instead
