"""Inside a worker container: run one group of approved steps, and say everything on stdout.

    python -m airlock.runner.executor < group.json

The launcher starts one container per group of consecutive steps for the same
worker profile, writes the group on stdin and reads stdout. Every record line
goes out as ``AIRLOCK-AUDIT <json>`` the moment it is written, and the last line
is ``AIRLOCK-RESULT <json>``. The launcher keeps the lines on its side of the
container boundary and verifies their chain, so the record does not live where
the operation runs.

Before the first step: the posture checks, which measure that the credentials in
this container are the worker's own and no wider than declared. Any failure and
nothing runs.

Each commands step is checked again here — the exact argv against this worker's
allowlist and the catastrophe floor — then run without a shell, with a deadline,
its output hashed, redacted and kept. The first step that does not succeed ends
the group; the rest are recorded as skipped. A task step (only for profiles that
allow task mode) runs an agent with the catastrophe floor as its gate and every
tool call recorded.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import socket
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from airlock.crypto import sha256_hex
from airlock.runner.engine import Engine, EngineRequest, StubEngine, StubTurn, ToolPolicy
from airlock.runner.gate import redact
from airlock.runner.guard import DANGER_ONLY, bash_deny_reason
from airlock.runner.posture import passed, run_checks
from airlock.runner.recorder import Recorder

AUDIT_PREFIX = "AIRLOCK-AUDIT "
RESULT_PREFIX = "AIRLOCK-RESULT "
TAIL_CHARS = 4000
LOG_LIMIT_BYTES = 5 * 1024 * 1024
EXIT_CODES = {"done": 0, "failed": 1, "refused": 3}


def _emit(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _refused(recorder: Recorder, step: Mapping[str, Any], reason: str) -> dict[str, Any]:
    recorder.write("step.refused", index=step.get("index"), target=step.get("target"), reason=reason)
    return {"index": step.get("index"), "target": step.get("target"), "status": "refused", "reason": reason}


def check_command(argv: list[str], allowlist: list[str]) -> str | None:
    """Why this argv may not run on this worker, or None."""
    text = shlex.join(argv)
    if not any(re.fullmatch(pattern, text) for pattern in allowlist):
        return f"`{text}` is not on this worker's command allowlist"
    return bash_deny_reason(text, DANGER_ONLY)


async def run_command(
    step: Mapping[str, Any], recorder: Recorder, *, cwd: Path, out_dir: Path | None
) -> dict[str, Any]:
    argv = [str(a) for a in step["argv"]]
    command, _ = redact(shlex.join(argv))
    index, target = step.get("index"), step.get("target")
    timeout = float(step.get("timeout_seconds") or 300)
    recorder.write("step.start", index=index, target=target, command=command, timeout_seconds=timeout)
    started = time.monotonic()
    status, exit_code, out, err = "done", 0, b"", b""
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(cwd),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(process.communicate(), timeout=timeout)
            exit_code = int(process.returncode or 0)
        except TimeoutError:
            process.kill()
            await process.wait()
            status, exit_code, err = "failed", 124, f"timed out after {timeout:.0f}s".encode()
    except FileNotFoundError:
        status, exit_code, err = "failed", 127, f"{argv[0]}: not found".encode()
    except OSError as exc:
        status, exit_code, err = "failed", 126, str(exc).encode()
    if exit_code != 0:
        status = "failed"
    duration_ms = int((time.monotonic() - started) * 1000)
    raw = out + (b"\n" if out and err else b"") + err
    text, flags = redact(raw.decode("utf-8", "replace"))
    log_error = None
    if out_dir is not None:
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"step-{index}.log").write_text(text[:LOG_LIMIT_BYTES], encoding="utf-8")
        except OSError as exc:
            log_error = f"the full output could not be kept: {exc}"[:200]
    outcome = {
        "index": index,
        "target": target,
        "command": command,
        "status": status,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "output_sha256": sha256_hex(out + b"\x00" + err),
        "tail": text[-TAIL_CHARS:],
        "redacted": flags,
    }
    if log_error:
        outcome["log_error"] = log_error
    recorder.write("step.end", **outcome)
    return outcome


def task_prompt(step: Mapping[str, Any], spec: Mapping[str, Any]) -> str:
    return (
        f"You are carrying out one approved step of plan {spec.get('plan_hash', '')[:12]} "
        f"as worker {spec.get('worker')}.\n\nTarget: {step.get('target')}\nWhy: {step.get('why', '')}\n"
        f"Permissions granted for this plan: {', '.join(spec.get('permissions') or []) or 'none listed'}\n\n"
        f"The step:\n```text\n{step.get('task', '')}\n```\n\n"
        "Do exactly this step on exactly this target and nothing else. If it cannot be done as written, "
        "stop and say why instead of improvising. End with what you did and how you checked it."
    )


async def run_task(
    step: Mapping[str, Any], spec: Mapping[str, Any], recorder: Recorder, *, cwd: Path, engine: Engine
) -> dict[str, Any]:
    index, target = step.get("index"), step.get("target")
    detail, _ = redact(str(step.get("task") or "")[:500])
    recorder.write("step.start", index=index, target=target, command=detail, mode="task")
    started = time.monotonic()
    policy = ToolPolicy(DANGER_ONLY, cwd, record=recorder.write)
    request = EngineRequest(
        prompt=task_prompt(step, spec),
        system="You are an airlock worker. You act only within the approved step you are given.",
        mode=DANGER_ONLY,
        workdir=cwd,
        timeout_seconds=float(step.get("timeout_seconds") or 300),
        max_turns=int(spec.get("max_turns") or 30),
        context={"step": dict(step)},
    )
    try:
        result = await engine.run(request, policy)
        error, text = result.error, result.text
    except Exception as exc:  # noqa: BLE001 — a crashed engine is a failed step, not a lost record
        error, text = f"{type(exc).__name__}: {exc}", ""
    clean, flags = redact(text)
    outcome = {
        "index": index,
        "target": target,
        "command": detail,
        "status": "failed" if error else "done",
        "exit_code": 1 if error else 0,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "output_sha256": sha256_hex(text.encode("utf-8", "replace")),
        "tail": (clean + (f"\n\nerror: {error}" if error else ""))[-TAIL_CHARS:],
        "redacted": flags,
        "tool_calls": policy.calls,
        "refusals": policy.refusals,
    }
    recorder.write("step.end", **outcome)
    return outcome


async def run_group(
    spec: Mapping[str, Any],
    recorder: Recorder,
    *,
    engine_factory: Callable[[], Engine] | None = None,
) -> dict[str, Any]:
    worker = str(spec.get("worker") or "")
    modes = list(spec.get("modes") or [])
    allowlist = [str(p) for p in spec.get("command_allowlist") or []]
    cwd = Path(str(spec.get("workdir") or "/tmp"))  # noqa: S108 — a fresh tmpfs inside the container
    out_dir = Path(spec["out_dir"]) if spec.get("out_dir") else None
    recorder.write(
        "group.start",
        approval_id=spec.get("approval_id"),
        plan_hash=spec.get("plan_hash"),
        work_id=spec.get("work_id"),
        group=spec.get("group"),
        worker=worker,
        steps=[s.get("index") for s in spec.get("steps") or []],
        permissions=list(spec.get("permissions") or []),
        host=socket.gethostname(),
        uid=os.getuid() if hasattr(os, "getuid") else None,
    )
    if not spec.get("steps") or not spec.get("approval_id"):
        reason = "the group names no approval or has no steps; nothing runs without both"
        recorder.write("group.end", status="refused", reason=reason)
        return {"status": "refused", "reason": reason, "steps": [], "posture": []}
    checks = await run_checks(list(spec.get("posture_checks") or []))
    for check in checks:
        recorder.write("posture.check" if check["ok"] else "posture.failed", **check)
    if not passed(checks):
        failed = ", ".join(c["name"] for c in checks if not c["ok"])
        reason = f"posture check failed: {failed}"
        recorder.write("group.end", status="refused", reason=reason)
        return {"status": "refused", "reason": reason, "steps": [], "posture": checks}

    status, reason, outcomes = "done", "", []
    for step in spec.get("steps") or []:
        if status != "done":
            recorder.write("step.skipped", index=step.get("index"), target=step.get("target"))
            outcomes.append({"index": step.get("index"), "target": step.get("target"), "status": "skipped"})
            continue
        if step.get("argv") is not None:
            problem = None if "commands" in modes else "this worker does not run commands steps"
            problem = problem or check_command([str(a) for a in step["argv"]], allowlist)
            if problem is not None:
                outcome = _refused(recorder, step, problem)
            else:
                outcome = await run_command(step, recorder, cwd=cwd, out_dir=out_dir)
        elif "task" not in modes:
            outcome = _refused(recorder, step, "this worker does not run task steps")
        else:
            engine = (engine_factory or default_engine)()
            outcome = await run_task(step, spec, recorder, cwd=cwd, engine=engine)
        outcomes.append(outcome)
        if outcome["status"] != "done":
            status = "refused" if outcome["status"] == "refused" else "failed"
            reason = outcome.get("reason") or f"step {step.get('index')} exited {outcome.get('exit_code')}"
    recorder.write("group.end", status=status, reason=reason)
    return {"status": status, "reason": reason, "steps": outcomes, "posture": checks}


def _stub_task(request: EngineRequest) -> StubTurn:
    """For tests and the demo: each line of the task that starts with ``$ `` is one Bash call."""
    task = str((request.context.get("step") or {}).get("task") or "")
    commands = [line[2:] for line in task.splitlines() if line.startswith("$ ")]
    return StubTurn(
        tools=[("Bash", {"command": c}) for c in commands],
        text=lambda t: "ran: " + "; ".join(f"{tool}={'refused' if out is None else 'ok'}" for tool, out in t.outputs),
    )


def default_engine() -> Engine:
    if os.environ.get("AIRLOCK_ENGINE", "claude") == "stub":
        return StubEngine(_stub_task, execute_bash=True)
    from airlock.runner.claude_engine import ClaudeEngine

    return ClaudeEngine(model=os.environ.get("AIRLOCK_MODEL") or None)


def main() -> int:
    spec = json.loads(sys.stdin.read() or "{}")
    recorder = Recorder(sink=lambda line: _emit(AUDIT_PREFIX + line))
    result = asyncio.run(run_group(spec, recorder))
    _emit(RESULT_PREFIX + json.dumps({**result, "record_head": recorder.head}, ensure_ascii=False, sort_keys=True))
    return EXIT_CODES.get(result["status"], 1)


if __name__ == "__main__":
    sys.exit(main())
