"""The executor that runs inside a worker container, exercised as a function and as the process the launcher starts."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from airlock.runner.engine import StubEngine, StubTurn
from airlock.runner.executor import AUDIT_PREFIX, RESULT_PREFIX, check_command, run_group
from airlock.runner.recorder import Recorder, verify_lines

pytestmark = pytest.mark.anyio

ALLOW = [r"echo [a-z0-9 .:-]+", "true", "false", r"sleep [0-9]+", r"sh -c .*"]


def spec(tmp_path: Path, steps: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {
        "approval_id": "a1",
        "plan_hash": "h" * 64,
        "work_id": "w1",
        "group": 1,
        "worker": "ops",
        "modes": ["commands"],
        "command_allowlist": ALLOW,
        "permissions": ["svc:restart"],
        "steps": [{"index": i, "target": "demo", "timeout_seconds": 10, **s} for i, s in enumerate(steps, 1)],
        "workdir": str(tmp_path),
        "out_dir": str(tmp_path / "out"),
        **extra,
    }


def recorder() -> tuple[Recorder, list[dict[str, Any]]]:
    lines: list[dict[str, Any]] = []
    return Recorder(sink=lambda text: lines.append(json.loads(text))), lines


def kinds(lines: list[dict[str, Any]]) -> list[str]:
    return [line["kind"] for line in lines]


async def test_commands_run_in_order_and_every_one_is_recorded(tmp_path: Path) -> None:
    rec, lines = recorder()
    result = await run_group(spec(tmp_path, [{"argv": ["echo", "restarting", "api"]}, {"argv": ["true"]}]), rec)
    assert result["status"] == "done"
    assert kinds(lines) == ["group.start", "step.start", "step.end", "step.start", "step.end", "group.end"]
    first = lines[2]["data"]
    assert first["exit_code"] == 0 and first["tail"].strip() == "restarting api" and len(first["output_sha256"]) == 64
    assert (tmp_path / "out" / "step-1.log").read_text().strip() == "restarting api"
    assert verify_lines(lines)["intact"]


async def test_the_first_failure_stops_the_group(tmp_path: Path) -> None:
    rec, lines = recorder()
    result = await run_group(spec(tmp_path, [{"argv": ["false"]}, {"argv": ["echo", "never"]}]), rec)
    assert result["status"] == "failed" and result["reason"] == "step 1 exited 1"
    assert kinds(lines)[-2:] == ["step.skipped", "group.end"]
    assert [s["status"] for s in result["steps"]] == ["failed", "skipped"]


async def test_the_allowlist_and_the_floor_are_checked_again_inside(tmp_path: Path) -> None:
    rec, lines = recorder()
    # Every refused command here would be harmless if it ran: a test must not be
    # one bug away from damaging the machine it runs on.
    result = await run_group(spec(tmp_path, [{"argv": ["rm", "-rf", "./does-not-exist"]}]), rec)
    assert result["status"] == "refused" and "not on this worker's command allowlist" in result["reason"]
    assert "step.start" not in kinds(lines)
    assert "danger guard: rm -rf" in str(check_command(["sh", "-c", "rm -rf ./does-not-exist"], ALLOW))
    assert check_command(["echo", "ok"], ALLOW) is None


async def test_a_step_past_its_deadline_is_killed(tmp_path: Path) -> None:
    rec, _ = recorder()
    result = await run_group(spec(tmp_path, [{"argv": ["sleep", "5"], "timeout_seconds": 1}]), rec)
    assert result["status"] == "failed" and result["steps"][0]["exit_code"] == 124


async def test_output_is_redacted_but_hashed(tmp_path: Path) -> None:
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    allow = [*ALLOW, r"printf [A-Z]+"]
    rec, lines = recorder()
    result = await run_group(spec(tmp_path, [{"argv": ["printf", key]}], command_allowlist=allow), rec)
    step = result["steps"][0]
    assert key not in step["tail"] and step["redacted"] == ["aws access key id"]
    assert key not in (tmp_path / "out" / "step-1.log").read_text()
    assert key not in json.dumps(lines)


async def test_a_failed_posture_check_runs_nothing(tmp_path: Path) -> None:
    rec, lines = recorder()
    checks = [
        {
            "name": "is the worker identity",
            "argv": ["echo", "arn:aws:iam::1:user/someone-else"],
            "expect": "user/airlock-worker$",
        }
    ]
    result = await run_group(spec(tmp_path, [{"argv": ["true"]}], posture_checks=checks), rec)
    assert result["status"] == "refused" and "is the worker identity" in result["reason"]
    assert kinds(lines) == ["group.start", "posture.failed", "group.end"]


async def test_a_passing_posture_check_is_recorded(tmp_path: Path) -> None:
    rec, lines = recorder()
    checks = [
        {"name": "identity", "argv": ["echo", "user/airlock-worker"], "expect": "user/airlock-worker$", "exit": 0}
    ]
    assert (await run_group(spec(tmp_path, [{"argv": ["true"]}], posture_checks=checks), rec))["status"] == "done"
    assert kinds(lines)[1] == "posture.check"


async def test_task_steps_run_an_agent_behind_the_floor(tmp_path: Path) -> None:
    def script(request: Any) -> StubTurn:
        return StubTurn(
            tools=[("Bash", {"command": "echo fixed"}), ("Bash", {"command": "rm -rf ./does-not-exist"})],
            text=lambda t: f"outputs: {[o for _, o in t.outputs]}",
        )

    rec, lines = recorder()
    task_spec = spec(tmp_path, [{"task": "restart the api"}], modes=["task"], worker="agent-ops")
    result = await run_group(task_spec, rec, engine_factory=lambda: StubEngine(script, execute_bash=True))
    assert result["status"] == "done"
    assert kinds(lines) == [
        "group.start",
        "step.start",
        "tool.call",
        "tool.result",
        "tool.refused",
        "step.end",
        "group.end",
    ]
    assert lines[4]["data"]["guard"] == "bash" and "rm -rf" in lines[4]["data"]["reason"]
    assert result["steps"][0]["refusals"] == 1 and "fixed" in lines[3]["data"]["tail"]


async def test_a_worker_runs_only_its_own_modes(tmp_path: Path) -> None:
    rec, _ = recorder()
    result = await run_group(spec(tmp_path, [{"task": "anything"}]), rec)
    assert result["status"] == "refused" and "does not run task steps" in result["reason"]
    rec, _ = recorder()
    result = await run_group(spec(tmp_path, [{"argv": ["true"]}], modes=["task"]), rec)
    assert result["status"] == "refused"


async def test_the_process_protocol_streams_the_record_and_ends_with_the_result(tmp_path: Path) -> None:
    payload = json.dumps(spec(tmp_path, [{"argv": ["echo", "hello"]}])).encode()
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "airlock.runner.executor",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )
    out, _ = await process.communicate(payload)
    rows = out.decode().splitlines()
    audit = [json.loads(r[len(AUDIT_PREFIX) :]) for r in rows if r.startswith(AUDIT_PREFIX)]
    result = json.loads(rows[-1][len(RESULT_PREFIX) :])
    assert process.returncode == 0 and rows[-1].startswith(RESULT_PREFIX)
    assert all(r.startswith((AUDIT_PREFIX, RESULT_PREFIX)) for r in rows), (
        "the command's own output must not reach stdout"
    )
    assert result["status"] == "done" and result["record_head"] == verify_lines(audit)["head"]


async def test_an_empty_or_anonymous_group_runs_nothing(tmp_path: Path) -> None:
    rec, lines = recorder()
    assert (await run_group({}, rec))["status"] == "refused"
    rec, lines = recorder()
    assert (await run_group(spec(tmp_path, [{"argv": ["true"]}], approval_id=""), rec))["status"] == "refused"
    assert kinds(lines) == ["group.start", "group.end"]
