"""A small MCP client for the chat platform: initialize once, then tools/call, with no agent in between.

None of the scan's calls needs judging. It lists conversations, compares
timestamps and fetches a window, and all of that is deterministic. A model
running those calls would cost what a quiet round should not: it would have to
finish the whole scan to learn there was nothing.

Three things learned against a real chat server, handled here once:

1. Answers may come as an event stream (``event: message`` plus ``data: {...}``)
   rather than bare JSON.
2. A failing tool can answer inside ``result`` (``isError``, or text that
   starts with "MCP error") rather than as a JSON-RPC error. Reading only
   ``error`` would take "no such tool" for success.
3. The data is in ``structuredContent``. ``content[0].text`` is a summary for
   people ("Found 6 message(s).") without a single message in it.

The platform's tool names carry its own prefix. That prefix is an internal
name, so it comes from the configuration (``tool_prefix``), never from code.
"""

from __future__ import annotations

import json
from typing import Any

import httpx


class McpError(RuntimeError):
    """The source could not be read. Callers must treat it as unreachable, never as quiet."""


def _message(response: httpx.Response, request_id: int) -> dict[str, Any]:
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        for line in response.text.splitlines():
            if line.startswith("data:"):
                try:
                    message = json.loads(line[5:].strip())
                except ValueError:
                    continue
                if isinstance(message, dict) and message.get("id") == request_id:
                    return message
        raise McpError(f"no answer to request {request_id} in the event stream")
    try:
        message = response.json()
    except ValueError as exc:
        raise McpError(f"the answer is not JSON: {response.text[:160]!r}") from exc
    if not isinstance(message, dict):
        raise McpError("the answer is not a JSON-RPC message")
    return message


class McpClient:
    def __init__(
        self,
        url: str,
        *,
        token: str = "",
        prefix: str = "",
        timeout: float = 60.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.url = url
        self.prefix = prefix
        self.headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self.http = httpx.Client(timeout=timeout, transport=transport)
        self.next_id = 0
        self.ready = False

    def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.next_id += 1
        body = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        try:
            response = self.http.post(self.url, json=body, headers=self.headers)
        except httpx.HTTPError as exc:
            raise McpError(f"{type(exc).__name__}: {str(exc)[:160]}") from exc
        if response.status_code >= 400:
            raise McpError(f"HTTP {response.status_code}: {response.text[:160]}")
        if response.headers.get("mcp-session-id"):
            self.headers["Mcp-Session-Id"] = response.headers["mcp-session-id"]
        return _message(response, self.next_id)

    def call(self, tool: str, **arguments: Any) -> dict[str, Any]:
        """The tool's structured result, or McpError."""
        if not self.ready:
            self._rpc(
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "airlock-watch", "version": "1"},
                },
            )
            self.ready = True
        answer = self._rpc("tools/call", {"name": f"{self.prefix}{tool}", "arguments": arguments})
        if "error" in answer:
            raise McpError(f"{tool}: {json.dumps(answer['error'], ensure_ascii=False)[:200]}")
        result = answer.get("result") or {}
        content = result.get("content") or [{}]
        text = str((content[0] if isinstance(content, list) and content else {}).get("text") or "")
        if result.get("isError") or text.startswith("MCP error"):
            raise McpError(f"{tool}: {text[:200]}")
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            raise McpError(f"{tool}: no structured result, only {text[:120]!r}")
        return structured

    def close(self) -> None:
        self.http.close()
