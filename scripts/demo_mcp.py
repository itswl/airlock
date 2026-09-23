"""A made-up MCP server for the demo: python scripts/demo_mcp.py (stdio), or --http PORT.

Two tools. `deploy_history` is what the demo's code investigator is allowed to
call; `restart_service` is there to be refused — it is not on the allowlist, so
the gate stops the call before this server ever sees it.

``--http PORT`` serves Streamable HTTP at /mcp in the SDK's default mode
(sessions, event streams), for scripts/mcpgate_check.py. There it stands in for
a server whose credential can write: when DEMO_MCP_TOKEN is set it answers only
``Authorization: Bearer $DEMO_MCP_TOKEN``, and when DEMO_MCP_LOG is set it
writes down every tool it runs, so a check can show what reached it.
"""

from __future__ import annotations

import argparse
import hmac
import os
from typing import Any

from mcp.server.mcpserver import MCPServer

server = MCPServer("demo")


def ran(tool: str, service: str) -> None:
    if os.environ.get("DEMO_MCP_LOG"):
        with open(os.environ["DEMO_MCP_LOG"], "a", encoding="utf-8") as log:
            log.write(f"{tool} {service}\n")


@server.tool()
def deploy_history(service: str) -> str:
    """Recent deploys of a service, newest last."""
    ran("deploy_history", service)
    return (
        f"2026-09-22T16:40Z {service} v2.13.2 deployed by ci (no config change)\n"
        f"2026-09-23T09:10Z {service} v2.14.0 deployed by ci: config/pool.yaml max_connections 20 -> 10 "
        "(commit 3f2a9c1 'tune pool for smaller db')"
    )


@server.tool()
def restart_service(service: str) -> str:
    """Restart a service."""
    ran("restart_service", service)
    return f"restarted {service}"


def guarded(app: Any, token: str) -> Any:
    """Answer only the bearer of the one credential, as a real server would."""
    expected = f"Bearer {token}".encode()

    async def guard(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            given = dict(scope["headers"]).get(b"authorization", b"")
            if not hmac.compare_digest(given, expected):
                await send(
                    {"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"text/plain")]}
                )
                await send({"type": "http.response.body", "body": b"no credential"})
                return
        await app(scope, receive, send)

    return guard


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--http", type=int, metavar="PORT", help="serve Streamable HTTP on 127.0.0.1:PORT/mcp")
    args = parser.parse_args()
    if args.http is None:
        server.run()
    else:
        import uvicorn

        app = server.streamable_http_app()
        if os.environ.get("DEMO_MCP_TOKEN"):
            app = guarded(app, os.environ["DEMO_MCP_TOKEN"])
        uvicorn.run(app, host="127.0.0.1", port=args.http, log_level="warning")
