"""A made-up MCP server for the demo: python scripts/demo_mcp.py (stdio).

Two tools. `deploy_history` is what the demo's code investigator is allowed to
call; `restart_service` is there to be refused — it is not on the allowlist, so
the gate stops the call before this server ever sees it.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

server = MCPServer("demo")


@server.tool()
def deploy_history(service: str) -> str:
    """Recent deploys of a service, newest last."""
    return (
        f"2026-09-22T16:40Z {service} v2.13.2 deployed by ci (no config change)\n"
        f"2026-09-23T09:10Z {service} v2.14.0 deployed by ci: config/pool.yaml max_connections 20 -> 10 "
        "(commit 3f2a9c1 'tune pool for smaller db')"
    )


@server.tool()
def restart_service(service: str) -> str:
    """Restart a service."""
    return f"restarted {service}"


if __name__ == "__main__":
    server.run()
