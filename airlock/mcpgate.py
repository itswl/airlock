"""MCP servers whose credential can write, behind one door that forwards the reads.

    python -m airlock.mcpgate --config /etc/airlock/mcp-gate.json [--host 0.0.0.0] [--port 8097] [--record calls.jsonl]

An investigator's MCP server reaches what its credential reaches, and the agent
runs as the same user in the same container, so it can read that credential.
Where a service issues read-only credentials, those go to the investigator
directly. Where it does not — one API key that lists alerts and also
acknowledges them — the server sits behind this gateway instead. The gateway
holds the credential. The investigator holds a token that is good only here,
and a call is forwarded only when it is one of the reads named for that server:

    {"servers": {"alerts": {"url": "https://alerts.example.com/mcp/",
                            "headers": {"Authorization": "Bearer ${ALERTS_API_KEY}"},
                            "tools": ["get_*", "list_*", "search_knowledge_base"]}},
     "clients": {"infra": {"token_env": "AIRLOCK_MCPGATE_INFRA_TOKEN", "servers": ["alerts"]}}}

The investigator names ``http://mcp-gate:8097/alerts/`` as a Streamable-HTTP
server and sends its token as ``Authorization: Bearer``. The gateway passes
the protocol's own messages (initialize, ping, notifications, listing and
reading). It forwards ``tools/call`` only for a tool matching the server's
patterns, and it drops every other tool from ``tools/list``, so the agent
never learns they exist. Anything else gets a JSON-RPC error here and never
reaches the server. Every tool call is recorded, whether forwarded or refused.

``${VAR}`` in a header value is read from the gateway's environment at start.
If the variable is unset, the gateway refuses to start rather than send an
empty credential.
"""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import hmac
import json
import os
import re
import sys
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from airlock import __version__
from airlock.runner.recorder import Recorder

# Requests of the protocol itself: setting up, listing, reading. None of them
# changes the server's data. tools/call can, so it is checked tool by tool.
PASSED = frozenset(
    {
        "initialize",
        "ping",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "resources/read",
        "prompts/list",
        "prompts/get",
        "completion/complete",
        "logging/setLevel",
    }
)
FORWARDED = ("accept", "content-type", "mcp-session-id", "mcp-protocol-version", "last-event-id")
RETURNED = ("content-type", "mcp-session-id", "mcp-protocol-version")
RESERVED = frozenset({"healthz"})
MIN_TOKEN = 16
_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_ARGUMENTS_KEPT = 2000


class GateConfigError(ValueError):
    """The gateway configuration cannot be used as written. The message says where."""


@dataclass(frozen=True)
class Upstream:
    name: str
    url: str
    headers: dict[str, str]
    tools: tuple[str, ...]

    def permits(self, tool: str) -> bool:
        return any(fnmatch.fnmatchcase(tool, pattern) for pattern in self.tools)


@dataclass(frozen=True)
class Client:
    name: str
    token: str
    servers: frozenset[str]


def _expand(value: str, environ: Mapping[str, str], where: str) -> str:
    def one(match: re.Match[str]) -> str:
        name = match.group(1)
        if not environ.get(name):
            raise GateConfigError(f"{where}: ${{{name}}} is not set in the gateway's environment")
        return environ[name]

    return _VAR.sub(one, value)


def load_gate(path: Path, environ: Mapping[str, str] | None = None) -> tuple[dict[str, Upstream], list[Client]]:
    env = os.environ if environ is None else environ
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GateConfigError(f"{path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise GateConfigError(f"{path}: not JSON ({exc})") from exc
    if not isinstance(data, dict) or not isinstance(data.get("servers"), dict) or not data["servers"]:
        raise GateConfigError(f'{path}: expected {{"servers": {{"<name>": {{...}}}}, "clients": {{...}}}}')
    servers: dict[str, Upstream] = {}
    for name, spec in data["servers"].items():
        where = f"{path}: server {name}"
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(name)) or name in RESERVED:
            raise GateConfigError(f"{where}: a name is letters, digits, - or _, and not {', '.join(sorted(RESERVED))}")
        if not isinstance(spec, dict):
            raise GateConfigError(f"{where} must be an object")
        url = str(spec.get("url") or "")
        if not url.startswith(("https://", "http://")):
            raise GateConfigError(f"{where}: url must be http(s)")
        tools = spec.get("tools")
        if not isinstance(tools, list) or not tools or not all(isinstance(t, str) and t for t in tools):
            raise GateConfigError(f"{where}: tools must list the tools it forwards (patterns like get_* are fine)")
        headers = spec.get("headers") or {}
        if not isinstance(headers, dict):
            raise GateConfigError(f"{where}: headers must be an object")
        servers[str(name)] = Upstream(
            name=str(name),
            url=url,
            headers={str(k): _expand(str(v), env, f"{where}, header {k}") for k, v in headers.items()},
            tools=tuple(tools),
        )
    clients: list[Client] = []
    for name, spec in (data.get("clients") or {}).items():
        where = f"{path}: client {name}"
        if not isinstance(spec, dict) or not spec.get("token_env"):
            raise GateConfigError(f"{where} needs token_env, the variable that holds its token")
        token = env.get(str(spec["token_env"]), "")
        if len(token) < MIN_TOKEN:
            raise GateConfigError(f"{where}: {spec['token_env']} is unset or shorter than {MIN_TOKEN} characters")
        allowed = spec.get("servers")
        if not isinstance(allowed, list) or not allowed:
            raise GateConfigError(f"{where}: servers must list the servers it may use")
        unknown = [s for s in allowed if s not in servers]
        if unknown:
            raise GateConfigError(f"{where}: no server named {', '.join(map(str, unknown))}")
        if any(hmac.compare_digest(token.encode(), other.token.encode()) for other in clients):
            raise GateConfigError(f"{where}: shares its token with another client, so the two cannot be told apart")
        clients.append(Client(name=str(name), token=token, servers=frozenset(allowed)))
    if not clients:
        raise GateConfigError(f"{path}: no clients, so nobody can use it")
    return servers, clients


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _key(request_id: Any) -> str:
    return json.dumps(request_id, sort_keys=True)


def _only_permitted(message: Any, listings: set[str], target: Upstream) -> Any:
    """Drop the tools this gateway would not forward from the answers to tools/list."""
    if isinstance(message, list):
        return [_only_permitted(item, listings, target) for item in message]
    if isinstance(message, dict) and "id" in message and _key(message["id"]) in listings:
        result = message.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            result["tools"] = [
                tool for tool in result["tools"] if isinstance(tool, dict) and target.permits(str(tool.get("name", "")))
            ]
    return message


def _filter_events(raw: bytes, listings: set[str], target: Upstream) -> bytes:
    """The same, for a text/event-stream answer: every data field is rewritten, the other fields are kept."""
    blocks = []
    for block in re.split(r"\r?\n\r?\n", raw.decode("utf-8")):
        if not block.strip():
            continue
        fields, data = [], []
        for line in block.splitlines():
            if line.startswith("data:"):
                data.append(line[6:] if line.startswith("data: ") else line[5:])
            else:
                fields.append(line)
        if data:
            text = "\n".join(data)
            with contextlib.suppress(ValueError):  # not JSON: passed on as it came
                text = json.dumps(_only_permitted(json.loads(text), listings, target), ensure_ascii=False)
            fields += [f"data: {part}" for part in text.split("\n")]
        blocks.append("\n".join(fields))
    return ("\n\n".join(blocks) + "\n\n").encode()


def create_gate_app(
    servers: dict[str, Upstream],
    clients: list[Client],
    *,
    record: Recorder | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    # trust_env=False: the gateway goes to the servers it was given, not through
    # whatever proxy its environment names.
    upstream = httpx.AsyncClient(
        transport=transport,
        trust_env=False,
        follow_redirects=False,
        timeout=httpx.Timeout(30.0, read=300.0),
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await upstream.aclose()

    app = FastAPI(
        title="airlock MCP gateway",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    def note(kind: str, **data: Any) -> None:
        if record is not None:
            record.write(kind, **data)

    def caller(request: Request) -> Client | None:
        header = request.headers.get("authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else ""
        found = None
        for client in clients:  # every one compared, so the time taken does not say which came close
            if token and hmac.compare_digest(token.encode(), client.token.encode()):
                found = client
        return found

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "servers": sorted(servers)}

    async def relay(server: str, request: Request) -> Response:
        client = caller(request)
        if client is None:
            return JSONResponse({"error": "this gateway needs a client token"}, status_code=401)
        target = servers.get(server)
        if target is None or server not in client.servers:
            return JSONResponse({"error": f"no server {server!r} for this client"}, status_code=404)
        body = await request.body() if request.method == "POST" else b""
        listings: set[str] = set()
        calls: list[dict[str, Any]] = []
        if request.method == "POST":
            try:
                message = json.loads(body)
            except ValueError:
                return JSONResponse(_error(None, -32700, "not JSON"), status_code=400)
            items = message if isinstance(message, list) else [message]
            refused: dict[str, dict[str, Any]] = {}
            for item in items:
                if not isinstance(item, dict):
                    return JSONResponse(_error(None, -32600, "not a JSON-RPC message"), status_code=400)
                method = item.get("method")
                if method is None or str(method).startswith("notifications/"):
                    continue  # the client's answer to the server's own request, or a notification
                if method == "tools/call":
                    params = item.get("params") if isinstance(item.get("params"), dict) else {}
                    tool = str(params.get("name") or "")
                    call = {
                        "client": client.name,
                        "server": server,
                        "tool": tool,
                        "arguments": json.dumps(params.get("arguments"), ensure_ascii=False)[:_ARGUMENTS_KEPT],
                    }
                    if target.permits(tool):
                        calls.append(call)
                    else:
                        note("call.refused", **call)
                        refused[_key(item.get("id"))] = _error(
                            item.get("id"), -32602, f"{tool} is not a tool this gateway forwards for {server}"
                        )
                elif method not in PASSED:
                    refused[_key(item.get("id"))] = _error(
                        item.get("id"), -32601, f"{method} is not forwarded by this gateway"
                    )
                elif method == "tools/list":
                    listings.add(_key(item.get("id")))
            if refused:
                # Nothing in a message that asks for a refused thing goes on: every request in it is answered here.
                answers = [
                    refused.get(_key(item.get("id")))
                    or _error(item.get("id"), -32600, "not forwarded: sent together with a refused request")
                    for item in items
                    if item.get("method") is not None and not str(item.get("method")).startswith("notifications/")
                ]
                return JSONResponse(answers if isinstance(message, list) else answers[0])
        headers = {name: value for name in FORWARDED if (value := request.headers.get(name))}
        headers.update(target.headers)
        outgoing = upstream.build_request(request.method, target.url, headers=headers, content=body or None)
        try:
            response = await upstream.send(outgoing, stream=True)
        except httpx.HTTPError as exc:
            for call in calls:
                note("call.failed", **call, reason=type(exc).__name__)
            return JSONResponse({"error": f"the server {server} could not be reached"}, status_code=502)
        for call in calls:
            note("call.forwarded", **call, status=response.status_code)
        returned = {name: value for name in RETURNED if (value := response.headers.get(name))}
        kind = response.headers.get("content-type", "")
        if listings and response.status_code == 200:
            raw = await response.aread()
            await response.aclose()
            if kind.startswith("application/json"):
                try:
                    raw = json.dumps(_only_permitted(json.loads(raw), listings, target), ensure_ascii=False).encode()
                except ValueError:
                    return JSONResponse({"error": f"the server {server} did not answer with JSON"}, status_code=502)
            elif kind.startswith("text/event-stream"):
                raw = _filter_events(raw, listings, target)
            else:
                return JSONResponse({"error": f"the server {server} answered tools/list as {kind!r}"}, status_code=502)
            return Response(raw, status_code=200, headers=returned)
        return StreamingResponse(
            response.aiter_bytes(),
            status_code=response.status_code,
            headers=returned,
            background=BackgroundTask(response.aclose),
        )

    for path in ("/{server}", "/{server}/"):
        app.add_api_route(path, relay, methods=["GET", "POST", "DELETE"], include_in_schema=False)
    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m airlock.mcpgate", description=__doc__.splitlines()[0])
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8097)
    parser.add_argument("--record", type=Path, help="a chained record of every tool call, forwarded or refused")
    args = parser.parse_args(argv)
    try:
        servers, clients = load_gate(args.config)
    except GateConfigError as exc:
        print(f"mcpgate: {exc}", file=sys.stderr)
        return 2
    import uvicorn

    record = Recorder(args.record) if args.record else None
    uvicorn.run(create_gate_app(servers, clients, record=record), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
