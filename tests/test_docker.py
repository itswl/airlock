"""The Docker runtime on a real Docker daemon. Opt-in: AIRLOCK_DOCKER_TESTS=1, with the image built first:

    docker build -f deploy/Dockerfile -t airlock:dev .
    AIRLOCK_DOCKER_TESTS=1 .venv/bin/python -m pytest tests/test_docker.py

Each container boundary is checked from inside the container, by the worker's
own posture checks, so the proof lands in the run's record like any other
step. Everything created is named airlock-test-* and removed afterwards.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from airlock.launcher.runtime import DockerRuntime
from airlock.launcher.service import Launcher
from tests.conftest import Router
from tests.test_launcher import Control, approval_for, make_launcher

IMAGE = os.environ.get("AIRLOCK_DOCKER_IMAGE", "airlock:dev")
pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(not os.environ.get("AIRLOCK_DOCKER_TESTS"), reason="needs Docker and the airlock:dev image"),
]

PYTHON_NET_PROBE = (
    "import socket\n"
    "try:\n"
    "    socket.create_connection(('1.1.1.1', 53), 3)\n"
    "    print('NET-OPEN')\n"
    "except OSError:\n"
    "    print('NET-CLOSED')\n"
)
BOUNDARIES: list[dict[str, Any]] = [
    {"name": "not root", "argv": ["id", "-u"], "expect": r"^(?!0$)\d+$"},
    {"name": "root filesystem is read-only", "argv": ["grep", " / ", "/proc/mounts"], "expect": r"^\S+ / \S+ ro[,\s]"},
    {"name": "no network", "argv": ["python", "-c", PYTHON_NET_PROBE], "expect": r"^NET-CLOSED$"},
    {"name": "no capabilities at all", "argv": ["grep", "CapBnd", "/proc/self/status"], "expect": r"CapBnd:\s+0{16}"},
    {"name": "no new privileges", "argv": ["grep", "NoNewPrivs", "/proc/self/status"], "expect": r"NoNewPrivs:\s+1"},
    {
        "name": "its own credentials, read-only",
        "argv": ["sh", "-c", "cat /airlock/creds/token; touch /airlock/creds/x 2>&1; echo rc=$?"],
        "expect": r"only-this-worker[\s\S]*rc=[1-9]",
    },
    {
        "name": "tmp cannot execute",
        "argv": ["sh", "-c", "cp /bin/true /tmp/t && /tmp/t; echo rc=$?"],
        "expect": r"rc=126",
    },
    {"name": "pids capped", "argv": ["cat", "/sys/fs/cgroup/pids.max"], "expect": r"^64$"},
    {"name": "memory capped", "argv": ["cat", "/sys/fs/cgroup/memory.max"], "expect": r"^536870912$"},
]


def worker(tmp_path: Path, **overrides: Any) -> dict[str, Any]:
    creds = tmp_path / "creds" / "box"
    creds.mkdir(parents=True, exist_ok=True)
    (creds / "token").write_text("only-this-worker\n")
    spec: dict[str, Any] = {
        "name": "ops",
        "modes": ["commands"],
        "image": IMAGE,
        "credentials_dir": str(creds),
        "allowed_permissions": ["svc:restart"],
        "command_allowlist": [r"echo [a-z0-9 .:-]+", "true", r"sleep [0-9]+"],
        "posture_checks": BOUNDARIES,
        "memory": "512m",
        "pids": 64,
    }
    spec.update(overrides)
    return spec


def docker_launcher(
    config_dict: dict[str, Any], env: dict[str, str], workers: list[dict[str, Any]]
) -> tuple[Launcher, Control]:
    launcher, control = make_launcher(config_dict, env, workers=workers)
    launcher.runtime = DockerRuntime()
    return launcher, control


def containers_for(approval_id: str) -> list[str]:
    out = subprocess.run(
        ["docker", "ps", "-aq", "--filter", f"label=airlock.approval={approval_id}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.split()


async def test_a_group_runs_in_a_container_that_proves_its_own_boundaries(
    tmp_path: Path, config_dict: dict[str, Any], env: dict[str, str]
) -> None:
    launcher, control = docker_launcher(config_dict, env, [worker(tmp_path)])
    plan = {
        "summary": "Say hello from a container",
        "changes": "Nothing changes.",
        "risk": "low",
        "permissions": {"ops": ["svc:restart"]},
        "steps": [
            {"worker": "ops", "target": "box", "argv": ["echo", "hello", "from", "a", "container"]},
            {"worker": "ops", "target": "box", "argv": ["true"]},
        ],
        "rollback": "None.",
        "verification": "The record says so.",
    }
    request = approval_for(plan, id=f"t{secrets.token_hex(4)}")
    assert launcher.accept(request).status == 202
    await asyncio.wait_for(launcher.drain(), timeout=120)
    result = control.results[0]
    assert result["status"] == "done", result
    group = result["groups"][0]
    assert group["isolation"] == "container" and group["record_intact"] and group["stray_output_lines"] == 0
    run_dir = Path(launcher.config.runs_dir) / request["approval"]["id"]
    streamed = [json.loads(line) for line in (run_dir / "group-1.jsonl").read_text().splitlines()]
    checks = {line["data"]["name"]: line["kind"] for line in streamed if line["kind"].startswith("posture.")}
    assert checks == {c["name"]: "posture.check" for c in BOUNDARIES}, checks
    assert (run_dir / "group-1" / "step-1.log").read_text().strip() == "hello from a container"
    assert containers_for(request["approval"]["id"]) == [], "--rm: nothing of the group is left"
    await launcher.close()


async def test_a_container_whose_posture_is_wrong_runs_nothing(
    tmp_path: Path, config_dict: dict[str, Any], env: dict[str, str]
) -> None:
    wrong = worker(tmp_path, posture_checks=[{"name": "must be root", "argv": ["id", "-u"], "expect": "^0$"}])
    launcher, control = docker_launcher(config_dict, env, [wrong])
    request = approval_for(
        {
            "summary": "s",
            "changes": "c",
            "risk": "low",
            "permissions": {"ops": ["svc:restart"]},
            "steps": [{"worker": "ops", "target": "box", "argv": ["true"]}],
            "rollback": "r",
            "verification": "v",
        },
        id=f"t{secrets.token_hex(4)}",
    )
    launcher.accept(request)
    await asyncio.wait_for(launcher.drain(), timeout=120)
    assert control.results[0]["status"] == "refused" and "must be root" in control.results[0]["reason"]
    await launcher.close()


def sleeper(seconds: int, approval: str) -> dict[str, Any]:
    return approval_for(
        {
            "summary": "s",
            "changes": "c",
            "risk": "low",
            "permissions": {"ops": ["svc:restart"]},
            "steps": [
                {"worker": "ops", "target": "box", "argv": ["sleep", str(seconds)], "timeout_seconds": seconds + 30}
            ],
            "rollback": "r",
            "verification": "v",
        },
        id=approval,
    )


async def wait_for_container(approval_id: str, within: float = 60) -> None:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if containers_for(approval_id):
            return
        await asyncio.sleep(0.5)
    raise AssertionError("the container never started")


async def gone(approval_id: str, within: float = 20) -> None:
    """Killed containers with --rm are removed a moment after they exit."""
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        if not containers_for(approval_id):
            return
        await asyncio.sleep(0.5)
    raise AssertionError(f"containers for {approval_id} are still there")


async def test_past_its_deadline_the_container_is_killed(
    tmp_path: Path, config_dict: dict[str, Any], env: dict[str, str]
) -> None:
    launcher, control = docker_launcher(config_dict, env, [worker(tmp_path, posture_checks=[], timeout_seconds=5)])
    request = sleeper(60, f"t{secrets.token_hex(4)}")
    launcher.accept(request)
    await asyncio.wait_for(launcher.drain(), timeout=120)
    assert control.results[0]["status"] == "failed" and "deadline" in control.results[0]["reason"]
    assert containers_for(request["approval"]["id"]) == []
    await launcher.close()


async def test_cancel_kills_the_container(tmp_path: Path, config_dict: dict[str, Any], env: dict[str, str]) -> None:
    launcher, control = docker_launcher(config_dict, env, [worker(tmp_path, posture_checks=[])])
    request = sleeper(60, f"t{secrets.token_hex(4)}")
    launcher.accept(request)
    await wait_for_container(request["approval"]["id"])
    assert (await launcher.cancel(request["approval"]["id"])).status == 200
    await asyncio.wait_for(launcher.drain(), timeout=60)
    assert control.results[0]["status"] == "cancelled"
    assert containers_for(request["approval"]["id"]) == []
    await launcher.close()


async def test_a_restarted_launcher_kills_what_it_left_running(
    tmp_path: Path, config_dict: dict[str, Any], env: dict[str, str]
) -> None:
    launcher, _ = docker_launcher(config_dict, env, [worker(tmp_path, posture_checks=[])])
    request = sleeper(60, f"t{secrets.token_hex(4)}")
    launcher.accept(request)
    await wait_for_container(request["approval"]["id"])
    # The launcher process dies; its container does not.
    for task in list(launcher.tasks.values()):
        task.cancel()
    await asyncio.gather(*launcher.tasks.values(), return_exceptions=True)
    assert containers_for(request["approval"]["id"]), "the container outlives the launcher that started it"

    control = Control(env["T_LAUNCHER"])
    router = Router()
    router.handle("control", control)
    restarted = Launcher(launcher.config, DockerRuntime(), client=httpx.AsyncClient(transport=router))
    await restarted.recover()
    await gone(request["approval"]["id"])
    assert await restarted.report_due() == 1 and "restarted" in control.results[0]["reason"]
    await launcher.close()
    await restarted.close()


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


CLIENT = """
import socket, sys
def direct():
    try:
        socket.create_connection(("1.1.1.1", 443), 3)
        return "open"
    except OSError:
        return "closed"
def through_proxy(target):
    s = socket.create_connection((sys.argv[1], 8888), 5)
    s.sendall(f"CONNECT {target} HTTP/1.1\\r\\nHost: {target}\\r\\n\\r\\n".encode())
    return s.recv(200).decode(errors="replace").split("\\r\\n")[0]
print("direct:", direct())
print("allowed:", through_proxy("example.com:443"))
print("unlisted host:", through_proxy("github.com:443"))
print("unlisted port:", through_proxy("example.com:22"))
"""


def test_an_investigator_network_has_one_way_out(tmp_path: Path) -> None:
    tag = secrets.token_hex(3)
    inside, outside, proxy = f"airlock-test-inside-{tag}", f"airlock-test-outside-{tag}", f"airlock-test-egress-{tag}"
    docker("network", "create", "--internal", inside)
    docker("network", "create", outside)
    try:
        docker(
            "run", "-d", "--rm", "--name", proxy, "--network", outside, "--read-only", "--cap-drop", "ALL",
            "-e", "EGRESS_ALLOW=example.com", "-e", "EGRESS_PORTS=443", IMAGE, "python", "-m", "airlock.egress.proxy",
        )  # fmt: skip
        docker("network", "connect", inside, proxy)
        time.sleep(1.5)
        out = docker("run", "--rm", "--network", inside, IMAGE, "python", "-c", CLIENT, proxy).stdout
        lines = dict(line.split(": ", 1) for line in out.strip().splitlines())
        assert lines["direct"] == "closed", "an internal network has no route out of its own"
        assert lines["allowed"].startswith("HTTP/1.1 200"), lines
        assert lines["unlisted host"].startswith("HTTP/1.1 403"), lines
        assert lines["unlisted port"].startswith("HTTP/1.1 403"), lines
        logs = docker("logs", proxy).stderr
        assert "REFUSED github.com:443" in logs and "REFUSED example.com:22" in logs
    finally:
        docker("rm", "-f", proxy, check=False)
        docker("network", "rm", inside, check=False)
        docker("network", "rm", outside, check=False)
