"""Where a group runs: a fresh Docker container per group, or (tests and the demo only) a local process.

The container is the boundary for the operation:

* ``--rm``: nothing survives the group, so no credential, file or process lingers;
* ``--read-only`` root, a small ``noexec`` tmpfs, ``--cap-drop ALL``,
  ``no-new-privileges``, a pids and a memory limit;
* the worker profile's credentials directory mounted read-only, and no other
  profile's — a container holds exactly one set of keys;
* ``--network`` from the profile, ``none`` when it names none, so reaching a
  target is something a profile is given rather than something it has;
* labels naming the approval, so a container found running can be traced to
  the plan that started it, and killed by it.

``LocalRuntime`` has none of that. It exists so the whole flow can be exercised
on a laptop without Docker, and every group it runs is recorded as
``isolation: none``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from airlock.config import WorkerProfile

OnLine = Callable[[str], Awaitable[None]]
CONTAINER_OUT = "/airlock/out"
CONTAINER_CREDS = "/airlock/creds"
CONTAINER_WORKSPACE = "/workspace"


@dataclass
class GroupSpec:
    approval_id: str
    work_id: str
    plan_hash: str
    group: int
    worker: WorkerProfile
    steps: list[dict[str, Any]]
    permissions: list[str]
    out_dir: Path
    engine: str = "claude"
    extra_env: Mapping[str, str] = field(default_factory=dict)
    # The fresh clone this group works in (airlock.launcher.workspace), when its worker has repos.
    workspace: Path | None = None

    @property
    def name(self) -> str:
        return f"airlock-{self.approval_id}-g{self.group}"

    @property
    def timeout(self) -> float:
        budget = sum(int(s.get("timeout_seconds") or 300) for s in self.steps) + 60
        return float(min(budget, self.worker.timeout_seconds))

    def env(self) -> dict[str, str]:
        """What the executor and every command it runs see, besides the profile's own settings."""
        return {
            **self.worker.env,
            **self.extra_env,
            "AIRLOCK_APPROVAL_ID": self.approval_id,
            "AIRLOCK_PLAN_HASH": self.plan_hash,
            "AIRLOCK_WORK_ID": self.work_id,
            "AIRLOCK_WORKER": self.worker.name,
            "AIRLOCK_ENGINE": self.engine,
            # AWS CLIs and SDKs append this to their User-Agent, which CloudTrail
            # keeps: the target's own audit log then names the approval.
            "AWS_SDK_UA_APP_ID": f"airlock-{self.approval_id}",
            # Commits made in a workspace say which worker and which approval made them.
            "GIT_AUTHOR_NAME": f"airlock {self.worker.name}",
            "GIT_AUTHOR_EMAIL": f"{self.worker.name}+{self.approval_id}@airlock.invalid",
            "GIT_COMMITTER_NAME": f"airlock {self.worker.name}",
            "GIT_COMMITTER_EMAIL": f"{self.worker.name}+{self.approval_id}@airlock.invalid",
        }

    def mounted_workspace(self) -> str | None:
        """The host directory mounted as the workspace: this run's clone, or the profile's fixed directory."""
        if self.workspace is not None:
            return str(self.workspace.resolve())
        return str(Path(self.worker.workspace_dir).resolve()) if self.worker.workspace_dir else None

    def payload(self, *, workdir: str, out_dir: str, credentials: str | None = None) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "work_id": self.work_id,
            "plan_hash": self.plan_hash,
            "group": self.group,
            "worker": self.worker.name,
            "modes": list(self.worker.modes),
            "command_allowlist": list(self.worker.command_allowlist),
            "posture_checks": [dict(c) for c in self.worker.posture_checks],
            "permissions": list(self.permissions),
            "steps": self.steps,
            "workdir": workdir,
            "out_dir": out_dir,
            "instructions": self.worker.instructions,
            "workspace_repo": self.steps[0].get("target") if self.workspace is not None else None,
            "credentials": credentials,
        }


@dataclass
class Exit:
    code: int
    timed_out: bool = False
    killed: bool = False


class Runtime(Protocol):
    isolation: str

    async def run(self, spec: GroupSpec, on_line: OnLine) -> Exit: ...

    async def kill(self, name: str) -> None: ...

    async def kill_approval(self, approval_id: str) -> None: ...


LINE_LIMIT = 2**20


async def _pump(process: asyncio.subprocess.Process, on_line: OnLine) -> None:
    assert process.stdout is not None
    while True:
        try:
            raw = await process.stdout.readline()
        except ValueError:
            # A line longer than LINE_LIMIT: drop it. It cannot be a record line
            # the executor wrote, and the chain check will say if one is missing.
            await process.stdout.read(LINE_LIMIT)
            await on_line("")
            continue
        if not raw:
            return
        await on_line(raw.decode("utf-8", "replace").rstrip("\n"))


async def _supervise(
    process: asyncio.subprocess.Process,
    spec: GroupSpec,
    stdin: bytes,
    on_line: OnLine,
    kill: Callable[[], Awaitable[None]],
) -> Exit:
    assert process.stdin is not None
    process.stdin.write(stdin)
    with contextlib.suppress(BrokenPipeError, ConnectionResetError):
        await process.stdin.drain()
    process.stdin.close()
    reader = asyncio.create_task(_pump(process, on_line))
    try:
        await asyncio.wait_for(process.wait(), timeout=spec.timeout)
    except TimeoutError:
        await kill()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(process.wait(), timeout=15)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader, timeout=5)
        return Exit(code=int(process.returncode or 124), timed_out=True)
    await reader
    return Exit(code=int(process.returncode or 0))


def default_user() -> str:
    """The launcher's own uid, so the step logs are its files; never root, even when the launcher is."""
    if not hasattr(os, "getuid") or os.getuid() == 0:
        return "65534:65534"
    return f"{os.getuid()}:{os.getgid()}"


def docker_argv(docker_bin: str, spec: GroupSpec) -> list[str]:
    """The exact ``docker run`` for one group. Pure, so the flags are testable without Docker."""
    worker = spec.worker
    argv = [
        docker_bin,
        "run",
        "--rm",
        "-i",
        "--name",
        spec.name,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",  # noqa: S108 — inside the container
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(worker.pids),
        "--memory",
        worker.memory,
        "--network",
        worker.network or "none",
        "--label",
        f"airlock.approval={spec.approval_id}",
        "--label",
        f"airlock.work={spec.work_id}",
        "--label",
        f"airlock.worker={worker.name}",
        "-v",
        f"{spec.out_dir.resolve()}:{CONTAINER_OUT}:rw",
    ]
    argv += ["--user", worker.user or default_user()]
    if worker.credentials_dir:
        argv += ["-v", f"{Path(worker.credentials_dir).resolve()}:{CONTAINER_CREDS}:ro"]
    workspace = spec.mounted_workspace()
    if workspace:
        argv += ["-v", f"{workspace}:{CONTAINER_WORKSPACE}:rw"]
    for key, value in sorted({"HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1", **spec.env()}.items()):  # noqa: S108
        argv += ["-e", f"{key}={value}"]
    argv += [worker.image, "python", "-m", "airlock.runner.executor"]
    return argv


class DockerRuntime:
    isolation = "container"

    def __init__(self, docker_bin: str = "docker") -> None:
        self.docker_bin = docker_bin

    async def run(self, spec: GroupSpec, on_line: OnLine) -> Exit:
        spec.out_dir.mkdir(parents=True, exist_ok=True)
        workdir = CONTAINER_WORKSPACE if spec.mounted_workspace() else "/tmp"  # noqa: S108
        credentials = CONTAINER_CREDS if spec.worker.credentials_dir else None
        stdin = json.dumps(spec.payload(workdir=workdir, out_dir=CONTAINER_OUT, credentials=credentials)).encode()
        with (spec.out_dir.parent / f"group-{spec.group}.stderr").open("wb") as stderr:
            process = await asyncio.create_subprocess_exec(
                *docker_argv(self.docker_bin, spec),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=stderr,
                limit=LINE_LIMIT,
            )
            return await _supervise(process, spec, stdin, on_line, lambda: self.kill(spec.name))

    async def kill(self, name: str) -> None:
        process = await asyncio.create_subprocess_exec(
            self.docker_bin, "kill", name, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        await process.wait()

    async def kill_approval(self, approval_id: str) -> None:
        """Every container an approval started, for a launcher that restarted while they ran."""
        process = await asyncio.create_subprocess_exec(
            self.docker_bin,
            "ps",
            "-q",
            "--filter",
            f"label=airlock.approval={approval_id}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await process.communicate()
        for container in out.decode().split():
            await self.kill(container)


class LocalRuntime:
    """The executor as a plain child process. No isolation at all: tests and the demo only."""

    isolation = "none"

    def __init__(self, python: str = sys.executable) -> None:
        self.python = python
        self.processes: dict[str, asyncio.subprocess.Process] = {}

    async def run(self, spec: GroupSpec, on_line: OnLine) -> Exit:
        spec.out_dir.mkdir(parents=True, exist_ok=True)
        workdir = spec.mounted_workspace() or str(spec.out_dir)
        stdin = json.dumps(
            spec.payload(workdir=workdir, out_dir=str(spec.out_dir), credentials=spec.worker.credentials_dir)
        ).encode()
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(spec.out_dir), **spec.env()}
        if "PYTHONPATH" in os.environ:
            env["PYTHONPATH"] = os.environ["PYTHONPATH"]
        with (spec.out_dir.parent / f"group-{spec.group}.stderr").open("wb") as stderr:
            process = await asyncio.create_subprocess_exec(
                self.python,
                "-m",
                "airlock.runner.executor",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=stderr,
                env=env,
                limit=LINE_LIMIT,
            )
            self.processes[spec.name] = process
            try:
                return await _supervise(process, spec, stdin, on_line, lambda: self.kill(spec.name))
            finally:
                self.processes.pop(spec.name, None)

    async def kill(self, name: str) -> None:
        process = self.processes.get(name)
        if process is not None and process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()

    async def kill_approval(self, approval_id: str) -> None:
        for name in [n for n in self.processes if n.startswith(f"airlock-{approval_id}-")]:
            await self.kill(name)
