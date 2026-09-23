"""The launcher's logic: check the approval again, run the plan group by group, keep the record, report.

It is deliberately suspicious of the control plane. Before a single container
starts, it checks on its own:

* the request is signed with the launcher's secret;
* the plan's hash, recomputed here, is the hash the approval names;
* the approval has not expired and has never been used before (single use,
  remembered across restarts);
* the plan is valid against the launcher's OWN copy of the worker profiles —
  a control plane that has been talked into something still cannot start a
  worker outside that list, with a command outside its allowlist, or with a
  permission the profile may not have;
* no other running plan holds any of its targets.

The record of a run lives here, outside every container: the launcher's own
chained record of what it started and how each container ended, plus every
line each executor streamed out, re-verified. A container that did not report
cleanly, or whose chain does not add up, is a failed group.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import httpx

from airlock.config import LauncherConfig
from airlock.control.service import Outcome
from airlock.crypto import canonical_json, sign
from airlock.db import Database
from airlock.launcher.runtime import GroupSpec, Runtime
from airlock.plans import PlanError, groups, parse_plan, plan_hash, targets, validate_plan
from airlock.runner.executor import AUDIT_PREFIX, RESULT_PREFIX
from airlock.runner.recorder import Recorder, verify_lines

logger = logging.getLogger("airlock.launcher")

SCHEMA = """
CREATE TABLE IF NOT EXISTS launches (
    approval_id TEXT PRIMARY KEY,
    work_id TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    received_at REAL NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    finished_at REAL,
    result TEXT,
    reported INTEGER NOT NULL DEFAULT 0,
    report_attempts INTEGER NOT NULL DEFAULT 0
);
"""

# Which executor lines the control plane hears about as they happen.
FORWARDED = frozenset(
    {
        "group.start",
        "posture.failed",
        "step.start",
        "step.end",
        "step.refused",
        "step.skipped",
        "tool.call",
        "tool.refused",
        "group.end",
    }
)


class Launcher:
    def __init__(
        self,
        config: LauncherConfig,
        runtime: Runtime,
        *,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.time,
        engine: str = "claude",
    ) -> None:
        self.config = config
        self.runtime = runtime
        self.client = client or httpx.AsyncClient(timeout=30.0)
        self.clock = clock
        self.engine = engine
        self.db = Database(config.db_path)
        self.db.script(SCHEMA)
        self.runs_dir = Path(config.runs_dir)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.refusals = Recorder(self.runs_dir / "refusals.jsonl")
        self.locks: dict[str, str] = {}
        self.current: dict[str, str] = {}
        self.cancelled: set[str] = set()
        self.tasks: dict[str, asyncio.Task[None]] = {}

    # ------------------------------------------------------------------ accept

    def accept(self, payload: Mapping[str, Any]) -> Outcome:
        approval = payload.get("approval")
        if not isinstance(approval, dict):
            return Outcome(400, {"reason": "approval is missing"})
        approval_id = str(approval.get("id") or "")
        if not approval_id:
            return Outcome(400, {"reason": "the approval has no id"})
        if self.db.one("SELECT 1 FROM launches WHERE approval_id = ?", [approval_id]):
            return Outcome(409, {"reason": "already launched: an approval starts one run"})
        try:
            plan = parse_plan(payload.get("plan"))
        except PlanError as exc:
            return self._refuse(approval, str(exc))
        digest = plan_hash(plan)
        if digest != approval.get("plan_hash"):
            return self._refuse(approval, "the plan's hash is not the approved hash")
        if float(approval.get("expires_at") or 0) < self.clock():
            return self._refuse(approval, "the approval has expired")
        errors = validate_plan(plan, self.config.workers)
        if errors:
            return self._refuse(
                approval, "the launcher's own worker profiles do not allow this plan: " + "; ".join(errors), errors
            )
        busy = sorted({self.locks[t] for t in targets(plan) if t in self.locks})
        if busy:
            held = [t for t in targets(plan) if t in self.locks]
            return Outcome(409, {"reason": f"busy: {', '.join(held)} is being changed by approval {', '.join(busy)}"})
        self.db.execute(
            "INSERT INTO launches (approval_id, work_id, plan_hash, received_at, status) VALUES (?,?,?,?,?)",
            [approval_id, str(approval.get("work_id") or ""), digest, self.clock(), "running"],
        )
        for target in targets(plan):
            self.locks[target] = approval_id
        run_dir = self.runs_dir / approval_id
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "approval.json").write_text(json.dumps(approval, indent=2, sort_keys=True), encoding="utf-8")
        (run_dir / "plan.json").write_text(
            json.dumps(plan.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8"
        )
        record = Recorder(run_dir / "launcher.jsonl")
        record.write("launch.accepted", approval=approval, plan_hash=digest, isolation=self.runtime.isolation)
        self.tasks[approval_id] = asyncio.create_task(self._run(approval, plan, record))
        return Outcome(202, {"status": "accepted"})

    def _refuse(self, approval: Mapping[str, Any], reason: str, errors: list[str] | None = None) -> Outcome:
        """A refusal is part of the record too: which approval, and why nothing started."""
        logger.warning("refused approval %s: %s", approval.get("id"), reason)
        self.refusals.write("launch.refused", approval=dict(approval), reason=reason, errors=errors or [])
        return Outcome(422, {"reason": reason, "errors": errors or []})

    # ------------------------------------------------------------------ run

    async def _post(self, path: str, payload: Mapping[str, Any]) -> httpx.Response:
        body = canonical_json(dict(payload))
        headers = {**sign(self.config.secret, body, now=self.clock()), "Content-Type": "application/json"}
        return await self.client.post(f"{self.config.control_url}{path}", content=body, headers=headers)

    def _progress_payload(
        self, approval: Mapping[str, Any], group: int, worker: str, line: Mapping[str, Any]
    ) -> dict[str, Any]:
        data = line.get("data") or {}
        kind = str(line.get("kind") or "")
        return {
            "approval_id": approval["id"],
            "plan_hash": approval["plan_hash"],
            "group": group,
            "worker": worker,
            "event": kind,
            "step": {
                "index": data.get("index"),
                "target": data.get("target"),
                "command": data.get("command") or data.get("detail") or data.get("reason") or data.get("name"),
                "status": data.get("status") or ("refused" if kind.endswith("refused") else ""),
                "exit_code": data.get("exit_code"),
                "duration_ms": data.get("duration_ms"),
                "tail": data.get("tail") or (data.get("detail") if kind == "posture.failed" else None),
                "output_sha256": data.get("output_sha256"),
            },
        }

    async def _send_progress(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Progress is best-effort and never holds up the run: a slow or absent control plane costs only the live view."""
        while True:
            payload = await queue.get()
            try:
                with contextlib.suppress(httpx.HTTPError):
                    await self._post("/v1/runs/progress", payload)
            finally:
                queue.task_done()

    async def _run_group(
        self, approval: Mapping[str, Any], spec: GroupSpec, record: Recorder, progress: asyncio.Queue[dict[str, Any]]
    ) -> dict[str, Any]:
        lines: list[dict[str, Any]] = []
        result: dict[str, Any] = {}
        noise = 0
        stream_path = spec.out_dir.parent / f"group-{spec.group}.jsonl"

        async def on_line(raw: str) -> None:
            nonlocal result, noise
            if raw.startswith(AUDIT_PREFIX):
                try:
                    line = json.loads(raw[len(AUDIT_PREFIX) :])
                except ValueError:
                    noise += 1
                    return
                lines.append(line)
                with stream_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(line, ensure_ascii=False, sort_keys=True) + "\n")
                if line.get("kind") in FORWARDED:
                    progress.put_nowait(self._progress_payload(approval, spec.group, spec.worker.name, line))
            elif raw.startswith(RESULT_PREFIX):
                with contextlib.suppress(ValueError):
                    result = json.loads(raw[len(RESULT_PREFIX) :])
            elif raw.strip():
                noise += 1

        self.current[approval["id"]] = spec.name
        record.write(
            "group.started",
            group=spec.group,
            worker=spec.worker.name,
            container=spec.name,
            image=spec.worker.image,
            isolation=self.runtime.isolation,
            steps=[s["index"] for s in spec.steps],
        )
        exit_info = await self.runtime.run(spec, on_line)
        self.current.pop(approval["id"], None)
        check = verify_lines(lines)
        ended = next((ln for ln in reversed(lines) if ln.get("kind") == "group.end"), None)
        status = str((ended or {}).get("data", {}).get("status") or "failed")
        reason = str((ended or {}).get("data", {}).get("reason") or "")
        if approval["id"] in self.cancelled:
            status, reason = "cancelled", "stopped by the operator"
        elif exit_info.timed_out:
            status, reason = "failed", f"the group ran past its {spec.timeout:.0f}s deadline and was killed"
        elif ended is None:
            status, reason = "failed", f"the container exited {exit_info.code} without finishing its record"
        elif not check["intact"]:
            status, reason = "failed", f"the record chain breaks at line {check['broken_at']}"
        elif result.get("record_head") and result.get("record_head") != check["head"]:
            status, reason = "failed", "the record the container reported is not the record it streamed"
        steps = [ln["data"] for ln in lines if ln.get("kind") in ("step.end", "step.refused", "step.skipped")]
        outcome = {
            "group": spec.group,
            "worker": spec.worker.name,
            "status": status,
            "reason": reason,
            "exit_code": exit_info.code,
            "isolation": self.runtime.isolation,
            "record_intact": check["intact"],
            "record_head": check["head"],
            "record_lines": check["checked"],
            "stray_output_lines": noise,
            "steps": steps,
        }
        record.write("group.finished", **{k: v for k, v in outcome.items() if k != "steps"})
        return outcome

    async def _run(self, approval: Mapping[str, Any], plan: Any, record: Recorder) -> None:
        approval_id = str(approval["id"])
        run_dir = self.runs_dir / approval_id
        outcomes: list[dict[str, Any]] = []
        status, reason = "done", ""
        progress: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        sender = asyncio.create_task(self._send_progress(progress))
        try:
            for index, group in enumerate(groups(plan), start=1):
                if approval_id in self.cancelled:
                    status, reason = "cancelled", "stopped by the operator"
                    break
                worker = self.config.workers[group["worker"]]
                spec = GroupSpec(
                    approval_id=approval_id,
                    work_id=str(approval.get("work_id") or ""),
                    plan_hash=str(approval["plan_hash"]),
                    group=index,
                    worker=worker,
                    steps=group["steps"],
                    permissions=list(plan.permissions.get(group["worker"]) or []),
                    out_dir=run_dir / f"group-{index}",
                    engine=self.engine,
                )
                outcome = await self._run_group(approval, spec, record, progress)
                outcomes.append(outcome)
                if outcome["status"] != "done":
                    status, reason = outcome["status"], outcome["reason"]
                    break
        except Exception as exc:  # noqa: BLE001 — every run ends with a report, whatever happened
            logger.exception("run %s crashed", approval_id)
            status, reason = "failed", f"the launcher failed while running: {type(exc).__name__}: {exc}"[:500]
        finally:
            for target, holder in list(self.locks.items()):
                if holder == approval_id:
                    del self.locks[target]
            self.cancelled.discard(approval_id)
            # Let the live view catch up before the final report closes the run on the far side.
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(progress.join(), timeout=10)
            sender.cancel()
        report = {
            "approval_id": approval_id,
            "plan_hash": approval["plan_hash"],
            "work_id": approval.get("work_id"),
            "status": status,
            "reason": reason,
            "isolation": self.runtime.isolation,
            "groups": outcomes,
            "record": str(run_dir),
        }
        record.write("launch.finished", status=status, reason=reason, groups=len(outcomes))
        report["launcher_record_head"] = record.head
        self.db.execute(
            "UPDATE launches SET status = ?, reason = ?, finished_at = ?, result = ? WHERE approval_id = ?",
            [status, reason, self.clock(), json.dumps(report, ensure_ascii=False), approval_id],
        )
        await self._report(approval_id, report)
        self.tasks.pop(approval_id, None)

    async def _report(self, approval_id: str, report: Mapping[str, Any]) -> bool:
        try:
            response = await self._post("/v1/runs/result", report)
            delivered = response.status_code == 200
        except httpx.HTTPError:
            delivered = False
        self.db.execute(
            "UPDATE launches SET reported = ?, report_attempts = report_attempts + 1 WHERE approval_id = ?",
            [1 if delivered else 0, approval_id],
        )
        return delivered

    async def report_due(self) -> int:
        """Results the control plane has not acknowledged yet, sent again."""
        rows = self.db.all(
            "SELECT approval_id, result FROM launches WHERE reported = 0 AND result IS NOT NULL LIMIT 20"
        )
        for row in rows:
            await self._report(row["approval_id"], json.loads(row["result"]))
        return len(rows)

    async def recover(self) -> None:
        """A run that was in flight when the launcher stopped is killed and reported failed, never resumed."""
        for row in self.db.all("SELECT * FROM launches WHERE status = 'running'"):
            with contextlib.suppress(Exception):
                await self.runtime.kill_approval(row["approval_id"])
            report = {
                "approval_id": row["approval_id"],
                "plan_hash": row["plan_hash"],
                "work_id": row["work_id"],
                "status": "failed",
                "reason": "the launcher restarted while this run was in flight; it was stopped, not resumed",
                "isolation": self.runtime.isolation,
                "groups": [],
                "record": str(self.runs_dir / row["approval_id"]),
            }
            self.db.execute(
                "UPDATE launches SET status = 'failed', reason = ?, finished_at = ?, result = ? WHERE approval_id = ?",
                [report["reason"], self.clock(), json.dumps(report), row["approval_id"]],
            )

    async def cancel(self, approval_id: str) -> Outcome:
        if approval_id not in self.tasks:
            return Outcome(404, {"reason": "no such run in flight"})
        self.cancelled.add(approval_id)
        name = self.current.get(approval_id)
        if name:
            await self.runtime.kill(name)
        return Outcome(200, {"status": "cancelling"})

    async def drain(self) -> None:
        while self.tasks:
            await asyncio.gather(*list(self.tasks.values()), return_exceptions=True)

    async def close(self) -> None:
        await self.client.aclose()
        self.db.close()
