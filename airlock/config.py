"""Configuration: profiles, sources, routes and secrets, loaded once and checked at load.

Secrets are never written in the file; each one names an environment variable
(``secret_env``) and an unset or empty variable is a load error. A door with no
secret must not open, and finding that out at start is better than at the first
request.

The control plane and the launcher load their configuration separately on
purpose. The launcher's copy of the worker profiles is the authoritative one: it
re-checks every plan against its own list, so a control plane that has been
talked into something still cannot start a worker outside that list.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

VERIFY_KINDS = ("github", "hub-signature", "hmac", "bearer")
MODES = ("commands", "task")


class ConfigError(ValueError):
    """The configuration cannot be run as written. The message says where."""


@dataclass(frozen=True)
class Source:
    """One door into the pipe.

    ``key`` (in ``templates``) names "the same thing": signals with one key are
    one alert, one issue, one ticket. ``dedup_seconds`` is how long a quiet
    spell may be before a repeat stops joining the open work item — measured
    from the last signal, so an alert that keeps firing keeps joining.
    ``continue_seconds`` is how long after a work item ended a repeat still
    continues its investigator's session in a new work item. ``split`` names a
    list in the payload (Alertmanager's ``alerts``) whose items are separate
    signals, so different alerts in one notification never share a session.
    """

    name: str
    verify: str
    secret: str
    accept: tuple[Mapping[str, Any], ...]
    templates: Mapping[str, str]
    labels: tuple[str, ...] = ()
    event_header: str | None = None
    dedup_seconds: int = 3600
    continue_seconds: int = 21600
    split: str | None = None


@dataclass(frozen=True)
class Route:
    investigator: str
    when: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class InvestigatorProfile:
    name: str
    url: str
    secret: str
    may_consult: tuple[str, ...] = ()


@dataclass(frozen=True)
class WorkerProfile:
    """What one kind of worker may do, and what its container is given.

    ``repos`` names the repositories this worker may change (name → a local git
    repository, usually a mirror). A step for it targets ``repo:<name>``; every
    run gets a fresh clone of that repository with no remote, and the launcher
    keeps what changed (airlock.launcher.workspace). ``instructions`` is added to
    every task step's prompt: the operator's rules for this worker, not the plan's.
    """

    name: str
    modes: tuple[str, ...] = ("commands",)
    allowed_permissions: tuple[str, ...] = ()
    command_allowlist: tuple[str, ...] = ()
    image: str = "airlock-runner:latest"
    credentials_dir: str | None = None
    workspace_dir: str | None = None
    repos: Mapping[str, str] = field(default_factory=dict)
    instructions: str = ""
    network: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    posture_checks: tuple[Mapping[str, Any], ...] = ()
    memory: str = "1g"
    pids: int = 256
    timeout_seconds: int = 1800
    user: str | None = None

    def allows_command(self, text: str) -> bool:
        return any(re.fullmatch(pattern, text) for pattern in self.command_allowlist)


@dataclass(frozen=True)
class Subscription:
    name: str
    url: str
    secret: str
    events: tuple[str, ...]

    def wants(self, event: str) -> bool:
        return "*" in self.events or event in self.events


@dataclass(frozen=True)
class Adapter:
    name: str
    secret: str
    identities: tuple[str, ...]


@dataclass(frozen=True)
class Operator:
    name: str
    password_hash: str


@dataclass(frozen=True)
class ControlConfig:
    base_url: str
    db_path: str
    session_secret: str
    operator: Operator
    sources: Mapping[str, Source]
    routes: tuple[Route, ...]
    investigators: Mapping[str, InvestigatorProfile]
    workers: Mapping[str, WorkerProfile]
    subscriptions: tuple[Subscription, ...]
    adapters: Mapping[str, Adapter]
    launcher_url: str
    launcher_secret: str
    approval_ttl_seconds: int = 86400
    max_consults: int = 5
    max_auto_revisions: int = 2
    investigation_timeout_seconds: int = 3600
    checkpoint_seconds: int = 3600

    @property
    def cookie_secure(self) -> bool:
        return self.base_url.startswith("https://")


@dataclass(frozen=True)
class LauncherConfig:
    db_path: str
    runs_dir: str
    control_url: str
    secret: str
    runtime: str
    workers: Mapping[str, WorkerProfile]
    docker_bin: str = "docker"


def _read(source: str | Path | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        return source
    data = yaml.safe_load(Path(source).read_text(encoding="utf-8")) or {}
    if not isinstance(data, Mapping):
        raise ConfigError(f"{source}: the top level must be a mapping")
    return data


def _secret(item: Mapping[str, Any], where: str, env: Mapping[str, str], key: str = "secret_env") -> str:
    name = str(item.get(key) or "")
    if not name:
        raise ConfigError(f"{where}: {key} is required — secrets are read from the environment, never from this file")
    value = env.get(name, "")
    if not value:
        raise ConfigError(f"{where}: environment variable {name} is unset or empty")
    return value


def _unique(names: list[str], what: str) -> None:
    seen: set[str] = set()
    for name in names:
        if not name or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", name):
            raise ConfigError(f"{what} name {name!r} must be lowercase letters, digits, - or _")
        if name in seen:
            raise ConfigError(f"{what} name {name!r} is used twice")
        seen.add(name)


def _workers(raw: list[Mapping[str, Any]]) -> dict[str, WorkerProfile]:
    _unique([str(w.get("name") or "") for w in raw], "worker")
    result: dict[str, WorkerProfile] = {}
    for item in raw:
        name = str(item["name"])
        modes = tuple(str(m) for m in item.get("modes") or ("commands",))
        for mode in modes:
            if mode not in MODES:
                raise ConfigError(f"worker {name}: mode {mode!r} is not one of {MODES}")
        allowlist = tuple(str(p) for p in item.get("command_allowlist") or ())
        for pattern in allowlist:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(f"worker {name}: command_allowlist pattern {pattern!r} is invalid: {exc}") from exc
        if "commands" in modes and not allowlist:
            raise ConfigError(
                f"worker {name}: commands mode needs a command_allowlist; an empty list would refuse every step"
            )
        checks = tuple(dict(c) for c in item.get("posture_checks") or ())
        for check in checks:
            if not isinstance(check.get("argv"), list) or not check.get("expect"):
                raise ConfigError(f"worker {name}: each posture check needs argv (a list) and expect (a regex)")
        repos = item.get("repos") or {}
        if not isinstance(repos, Mapping):
            raise ConfigError(f"worker {name}: repos maps a name to a local git repository")
        for repo, path in repos.items():
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", str(repo)):
                raise ConfigError(f"worker {name}: repository name {repo!r} must be letters, digits, ., - or _")
            if not str(path).startswith("/"):
                raise ConfigError(f"worker {name}: repository {repo} must be an absolute path")
        if repos and item.get("workspace_dir"):
            raise ConfigError(
                f"worker {name}: workspace_dir and repos are two answers to one question; a worker has one of them"
            )
        result[name] = WorkerProfile(
            name=name,
            modes=modes,
            allowed_permissions=tuple(str(p) for p in item.get("allowed_permissions") or ()),
            command_allowlist=allowlist,
            image=str(item.get("image") or "airlock-runner:latest"),
            credentials_dir=item.get("credentials_dir"),
            workspace_dir=item.get("workspace_dir"),
            repos={str(k): str(v) for k, v in repos.items()},
            instructions=str(item.get("instructions") or ""),
            network=item.get("network"),
            env={str(k): str(v) for k, v in (item.get("env") or {}).items()},
            posture_checks=checks,
            memory=str(item.get("memory") or "1g"),
            pids=int(item.get("pids") or 256),
            timeout_seconds=int(item.get("timeout_seconds") or 1800),
            user=str(item["user"]) if item.get("user") else None,
        )
    return result


def load_control(source: str | Path | Mapping[str, Any], env: Mapping[str, str] | None = None) -> ControlConfig:
    env = os.environ if env is None else env
    data = _read(source)
    control = data.get("control") or {}

    sources_raw = list(data.get("sources") or [])
    _unique([str(s.get("name") or "") for s in sources_raw], "source")
    sources: dict[str, Source] = {}
    for item in sources_raw:
        name = str(item["name"])
        verify = str(item.get("verify") or "")
        if verify not in VERIFY_KINDS:
            raise ConfigError(f"source {name}: verify must be one of {VERIFY_KINDS}")
        if "accept" not in item:
            raise ConfigError(f"source {name}: say which events become work with accept; use [{{}}] to take all")
        default_header = "X-GitHub-Event" if verify == "github" else None
        sources[name] = Source(
            name=name,
            verify=verify,
            secret=_secret(item, f"source {name}", env),
            accept=tuple(dict(rule.get("when") or {}) for rule in item.get("accept") or []),
            templates={str(k): str(v) for k, v in (item.get("map") or {}).items()},
            labels=tuple(str(label) for label in item.get("labels") or ()),
            event_header=item.get("event_header", default_header),
            dedup_seconds=int(item.get("dedup_seconds", 3600)),
            continue_seconds=int(item.get("continue_seconds", 21600)),
            split=str(item["split"]) if item.get("split") else None,
        )

    inv_raw = list(data.get("investigators") or [])
    _unique([str(i.get("name") or "") for i in inv_raw], "investigator")
    investigators = {
        str(item["name"]): InvestigatorProfile(
            name=str(item["name"]),
            url=str(item.get("url") or "").rstrip("/"),
            secret=_secret(item, f"investigator {item['name']}", env),
            may_consult=tuple(str(n) for n in item.get("may_consult") or ()),
        )
        for item in inv_raw
    }
    for profile in investigators.values():
        if not profile.url:
            raise ConfigError(f"investigator {profile.name}: url is required")
        for other in profile.may_consult:
            if other not in investigators or other == profile.name:
                raise ConfigError(
                    f"investigator {profile.name}: may_consult names {other!r}, which is not another investigator"
                )

    routes = tuple(
        Route(investigator=str(item["investigator"]), when=dict(item["when"]) if item.get("when") else None)
        for item in data.get("routes") or []
    )
    for route in routes:
        if route.investigator not in investigators:
            raise ConfigError(f"route to {route.investigator!r}: no investigator by that name")
    if not routes:
        raise ConfigError("routes: at least one route is needed, or no signal could reach an investigator")

    subscriptions = tuple(
        Subscription(
            name=str(item["name"]),
            url=str(item["url"]),
            secret=_secret(item, f"subscription {item['name']}", env),
            events=tuple(str(e) for e in item.get("events") or ("*",)),
        )
        for item in data.get("subscriptions") or []
    )
    _unique([s.name for s in subscriptions], "subscription")

    adapters_raw = list(data.get("adapters") or [])
    _unique([str(a.get("name") or "") for a in adapters_raw], "adapter")
    adapters = {
        str(item["name"]): Adapter(
            name=str(item["name"]),
            secret=_secret(item, f"adapter {item['name']}", env),
            identities=tuple(str(i) for i in item.get("identities") or ()),
        )
        for item in adapters_raw
    }

    operator_raw = data.get("operator") or {}
    password_hash = env.get(str(operator_raw.get("password_hash_env") or "AIRLOCK_OPERATOR_PASSWORD_HASH"), "")
    if not password_hash.startswith("scrypt$"):
        raise ConfigError(
            "operator: the password hash environment variable is unset; generate one with python -m airlock.control.passwd"
        )

    launcher_raw = data.get("launcher") or {}
    if not launcher_raw.get("url"):
        raise ConfigError("launcher: url is required — approved plans go nowhere else")
    operator_name = str(operator_raw.get("name") or "operator")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", operator_name):
        raise ConfigError("operator: name must be letters, digits, '.', '-' or '_'")
    return ControlConfig(
        base_url=str(control.get("base_url") or "http://127.0.0.1:8080").rstrip("/"),
        db_path=str(control.get("db_path") or "data/control.db"),
        session_secret=_secret(control, "control", env, key="session_secret_env"),
        operator=Operator(name=operator_name, password_hash=password_hash),
        sources=sources,
        routes=routes,
        investigators=investigators,
        workers=_workers(list(data.get("workers") or [])),
        subscriptions=subscriptions,
        adapters=adapters,
        launcher_url=str(launcher_raw.get("url") or "").rstrip("/"),
        launcher_secret=_secret(launcher_raw, "launcher", env),
        approval_ttl_seconds=int(control.get("approval_ttl_seconds", 86400)),
        max_consults=int(control.get("max_consults", 5)),
        max_auto_revisions=int(control.get("max_auto_revisions", 2)),
        investigation_timeout_seconds=int(control.get("investigation_timeout_seconds", 3600)),
        checkpoint_seconds=int(control.get("checkpoint_seconds", 3600)),
    )


def load_launcher(source: str | Path | Mapping[str, Any], env: Mapping[str, str] | None = None) -> LauncherConfig:
    env = os.environ if env is None else env
    data = _read(source)
    launcher = data.get("launcher") or {}
    runtime = str(launcher.get("runtime") or "docker")
    if runtime not in ("docker", "local"):
        raise ConfigError("launcher: runtime must be docker or local")
    if not launcher.get("control_url"):
        raise ConfigError("launcher: control_url is required — results are reported there")
    return LauncherConfig(
        db_path=str(launcher.get("db_path") or "data/launcher.db"),
        runs_dir=str(launcher.get("runs_dir") or "runs"),
        control_url=str(launcher.get("control_url") or "").rstrip("/"),
        secret=_secret(launcher, "launcher", env),
        runtime=runtime,
        workers=_workers(list(data.get("workers") or [])),
        docker_bin=str(launcher.get("docker_bin") or "docker"),
    )
