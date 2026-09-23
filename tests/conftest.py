"""Shared fixtures: a complete configuration with fake secrets, and in-process HTTP between the parts.

Nothing here touches the network, Docker, a model, or any file outside pytest's
temporary directory. Every secret is generated per test run.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from airlock.control.auth import hash_password
from airlock.crypto import canonical_json, sign

PASSWORD = "correct horse battery staple"
_HASH = hash_password(PASSWORD)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def env() -> dict[str, str]:
    names = ["SESSION", "LAUNCHER", "GITHUB", "ALERTS", "CI", "INFRA", "CODE", "HOOKS", "CHAT"]
    values = {f"T_{name}": secrets.token_hex(16) for name in names}
    values["T_PASSWORD_HASH"] = _HASH
    return values


def make_config(tmp_path: Path) -> dict[str, Any]:
    return {
        "control": {
            "base_url": "http://control",
            "db_path": str(tmp_path / "control.db"),
            "session_secret_env": "T_SESSION",
            "approval_ttl_seconds": 3600,
            "max_consults": 2,
            "max_auto_revisions": 1,
        },
        "operator": {"name": "operator", "password_hash_env": "T_PASSWORD_HASH"},
        "launcher": {
            "url": "http://launcher",
            "secret_env": "T_LAUNCHER",
            "control_url": "http://control",
            "db_path": str(tmp_path / "launcher.db"),
            "runs_dir": str(tmp_path / "runs"),
            "runtime": "local",
        },
        "sources": [
            {
                "name": "github",
                "verify": "github",
                "secret_env": "T_GITHUB",
                "accept": [{"when": {"event": "issues", "action": "labeled", "label.name": "airlock"}}],
                "map": {
                    "title": "{issue.title}",
                    "body": "{issue.body}",
                    "url": "{issue.html_url}",
                    "key": "{repository.full_name}#{issue.number}",
                },
                "labels": ["github"],
            },
            {
                "name": "alerts",
                "verify": "hmac",
                "secret_env": "T_ALERTS",
                "accept": [{"when": {"status": "firing"}}],
                "map": {"title": "{alertname}: {summary}", "body": "{description}", "key": "{fingerprint}"},
                "dedup_seconds": 600,
            },
            {"name": "ci", "verify": "bearer", "secret_env": "T_CI", "accept": [{}]},
        ],
        "routes": [
            {"when": {"source": "github"}, "investigator": "code"},
            {"investigator": "infra"},
        ],
        "investigators": [
            {"name": "infra", "url": "http://infra", "secret_env": "T_INFRA", "may_consult": ["code"]},
            {"name": "code", "url": "http://code", "secret_env": "T_CODE"},
        ],
        "workers": [
            {
                "name": "ops",
                "modes": ["commands"],
                "allowed_permissions": ["svc:restart", "svc:read"],
                "command_allowlist": [r"echo [a-z0-9 .:-]+", "true", "false", r"sleep [0-9]+"],
            },
            {"name": "agent-ops", "modes": ["task"], "allowed_permissions": ["svc:restart"]},
        ],
        "subscriptions": [{"name": "hooks", "url": "http://hooks/in", "secret_env": "T_HOOKS", "events": ["*"]}],
        "adapters": [{"name": "chat", "secret_env": "T_CHAT", "identities": ["u-123"]}],
    }


@pytest.fixture
def config_dict(tmp_path: Path) -> dict[str, Any]:
    return make_config(tmp_path)


def plan_doc(**overrides: Any) -> dict[str, Any]:
    plan: dict[str, Any] = {
        "summary": "Restart the demo service",
        "changes": "The demo service restarts once.",
        "risk": "low",
        "permissions": {"ops": ["svc:restart"]},
        "steps": [
            {"worker": "ops", "target": "demo/api", "argv": ["echo", "restarting", "api"], "why": "clears the pool"},
            {"worker": "ops", "target": "demo/api", "argv": ["true"], "why": "health check"},
        ],
        "rollback": "Nothing to roll back.",
        "verification": "Health endpoint answers 200.",
    }
    plan.update(overrides)
    return plan


def fenced(plan: Mapping[str, Any], prose: str = "Findings: the pool is exhausted.") -> str:
    return f"{prose}\n\n```plan\n{json.dumps(plan, indent=2)}\n```\n"


def signed(secret: str, payload: Mapping[str, Any], **headers: str) -> tuple[bytes, dict[str, str]]:
    body = canonical_json(dict(payload))
    return body, {**sign(secret, body), "Content-Type": "application/json", **headers}


class Router(httpx.AsyncBaseTransport):
    """Send each request to the in-process app registered for its host; record anything else."""

    def __init__(self, apps: Mapping[str, Any] | None = None) -> None:
        self.apps = dict(apps or {})
        self.handlers: dict[str, Callable[[httpx.Request], httpx.Response]] = {}
        self.sent: list[httpx.Request] = []

    def mount(self, host: str, app: Any) -> None:
        self.apps[host] = app

    def handle(self, host: str, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.handlers[host] = handler

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.sent.append(request)
        host = request.url.host
        if host in self.handlers:
            await request.aread()
            return self.handlers[host](request)
        app = self.apps.get(host)
        if app is None:
            raise httpx.ConnectError(f"no route to {host}", request=request)
        return await httpx.ASGITransport(app=app).handle_async_request(request)


def body_of(request: httpx.Request) -> dict[str, Any]:
    return json.loads(request.content)
