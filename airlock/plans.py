"""The plan: the one artifact that crosses from the read-only side to the side that writes.

Its shape is fixed so that approving it means something. Every step names the
worker profile that runs it and the target it touches; a commands step is an
argv, never a shell string; the permissions each worker needs are listed up
front. ``plan_hash`` over the canonical JSON is what an approval binds to, so a
plan that changes by one character after you approved it is a different plan.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from airlock.config import WorkerProfile
from airlock.crypto import canonical_json, sha256_hex
from airlock.runner.guard import DANGER_ONLY, bash_deny_reason

REPO_TARGET = "repo:"  # a step on a worker with repositories targets repo:<name>


class PlanError(ValueError):
    """The text does not contain a usable plan. The message is written for the investigator to act on."""


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")

    worker: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=200)
    argv: list[str] | None = None
    task: str | None = Field(default=None, max_length=8000)
    why: str = Field(default="", max_length=2000)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)

    @model_validator(mode="after")
    def _one_mode(self) -> Step:
        if (self.argv is None) == (self.task is None):
            raise ValueError("a step has exactly one of argv or task")
        if self.argv is not None:
            if not self.argv:
                raise ValueError("argv is empty")
            for arg in self.argv:
                if "\x00" in arg or len(arg) > 4096:
                    raise ValueError("argv items must be plain strings under 4096 characters")
        return self

    @property
    def mode(self) -> str:
        return "commands" if self.argv is not None else "task"

    @property
    def command_text(self) -> str:
        return shlex.join(self.argv or [])


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=500)
    changes: str = Field(min_length=1, max_length=4000)
    rollback: str = Field(min_length=1, max_length=4000)
    risk: Literal["low", "medium", "high"]
    verification: str = Field(min_length=1, max_length=4000)
    evidence: str = Field(default="", max_length=8000)
    permissions: dict[str, list[str]] = Field(default_factory=dict)
    steps: list[Step] = Field(min_length=1, max_length=50)


def plan_hash(plan: Plan) -> str:
    return sha256_hex(canonical_json(plan.model_dump(mode="json")))


def validate_plan(plan: Plan, workers: Mapping[str, WorkerProfile]) -> list[str]:
    """Everything that makes this plan impossible to run as written. Empty means approvable."""
    errors: list[str] = []
    used: set[str] = set()
    for index, step in enumerate(plan.steps, start=1):
        profile = workers.get(step.worker)
        if profile is None:
            errors.append(f"step {index}: there is no worker profile named {step.worker!r}")
            continue
        used.add(step.worker)
        if step.mode not in profile.modes:
            errors.append(f"step {index}: worker {step.worker} does not run {step.mode} steps")
            continue
        if profile.repos:
            repo = step.target[len(REPO_TARGET) :] if step.target.startswith(REPO_TARGET) else None
            if repo not in profile.repos:
                names = ", ".join(f"{REPO_TARGET}{r}" for r in sorted(profile.repos))
                errors.append(
                    f"step {index}: worker {step.worker} changes repositories, so its target is one of {names}"
                )
        if step.mode == "commands":
            text = step.command_text
            if not profile.allows_command(text):
                errors.append(f"step {index}: `{text}` is not on worker {step.worker}'s command allowlist")
            floor = bash_deny_reason(text, DANGER_ONLY)
            if floor is not None:
                errors.append(f"step {index}: {floor}")
    for worker in sorted(used):
        needed = plan.permissions.get(worker)
        if needed is None:
            errors.append(f"permissions: worker {worker} runs steps but the plan does not say what it needs")
            continue
        extra = sorted(set(needed) - set(workers[worker].allowed_permissions))
        if extra:
            errors.append(f"permissions: worker {worker} may not have {', '.join(extra)}")
    for worker in sorted(set(plan.permissions) - used):
        errors.append(f"permissions: {worker} is listed but runs no step")
    return errors


def groups(plan: Plan) -> list[dict[str, Any]]:
    """Consecutive steps on the same worker, in order. Each group becomes one container.

    A container mounts one repository, so consecutive steps on different
    ``repo:`` targets are separate groups even when the worker is the same.
    """
    result: list[dict[str, Any]] = []
    for index, step in enumerate(plan.steps, start=1):
        entry = {"index": index, **step.model_dump(mode="json")}
        repo = step.target if step.target.startswith(REPO_TARGET) else None
        if result and result[-1]["worker"] == step.worker and result[-1]["repo"] == repo:
            result[-1]["steps"].append(entry)
        else:
            result.append({"worker": step.worker, "repo": repo, "steps": [entry]})
    return result


def targets(plan: Plan) -> list[str]:
    return sorted({step.target for step in plan.steps})


_FENCE = re.compile(r"```(plan|json)\s*\n(.*?)\n```", re.DOTALL)


def _plan_fences(text: str) -> list[re.Match[str]]:
    """Fences that are meant as a plan: ```plan, or ```json holding "steps". Other code blocks are evidence."""
    return [m for m in _FENCE.finditer(text or "") if m.group(1) == "plan" or '"steps"' in m.group(2)]


def has_plan(text: str) -> bool:
    return bool(_plan_fences(text))


def strip_plans(text: str) -> str:
    """The prose around the plan, with every other code block kept."""
    for match in reversed(_plan_fences(text)):
        text = text[: match.start()] + text[match.end() :]
    return text.strip()


def extract_plan(text: str) -> Plan:
    """The last fenced ```plan block in ``text`` (or a ```json one that has steps), validated."""
    fences = _plan_fences(text)
    chosen = next((m.group(2) for m in reversed(fences) if m.group(1) == "plan"), None)
    if chosen is None and fences:
        chosen = fences[-1].group(2)
    if chosen is None:
        raise PlanError("no ```plan block was found; end the answer with one JSON plan in a ```plan fence")
    try:
        data = json.loads(chosen)
    except json.JSONDecodeError as exc:
        raise PlanError(f"the ```plan block is not valid JSON: {exc}") from exc
    return parse_plan(data)


def parse_plan(data: Any) -> Plan:
    try:
        return Plan.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors())
        raise PlanError(f"the plan does not match the schema: {problems}") from exc
