"""The engine seam: one agent turn, with every tool call passing through a policy first.

An engine turns a prompt into text. What it may do on the way is not its
business: every tool call is put to a ``ToolPolicy`` before it runs, which asks
the gate (read-only for investigators, catastrophe floor for task-mode workers)
and records the call either way. The Claude engine wires the policy into the
SDK's hooks; the stub engine here calls it directly, so the tests and the demo
exercise the same gate a real run does.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from airlock.crypto import sha256_hex
from airlock.runner.gate import deny_reason, private_reason, redact
from airlock.runner.sandbox import CONSULT_TOOL, confine_reason

__all__ = ["CONSULT_TOOL", "Engine", "EngineRequest", "EngineResult", "StubEngine", "StubTurn", "ToolPolicy"]
Consult = Callable[[str, str], Awaitable[str]]
Record = Callable[..., Any]


@dataclass(frozen=True)
class EngineRequest:
    prompt: str
    system: str
    mode: str
    workdir: Path
    session: str | None = None
    # With ``session``: branch a new session off it instead of appending to it,
    # so a sequel starts from what the earlier investigation knew and the
    # earlier session stays exactly as it was.
    fork_session: bool = False
    consult: Consult | None = None
    consultable: tuple[str, ...] = ()
    mcp_allowed: frozenset[str] = frozenset()
    max_turns: int = 40
    timeout_seconds: float = 1800.0
    # The structured input behind the prompt. The Claude engine ignores it; the
    # stub reads it so a scripted turn can answer without parsing prose.
    context: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EngineResult:
    text: str
    session: str | None = None
    # As the engine reports it. For the Claude CLI this is its own price table,
    # not the gateway's, and it accumulates across a resumed session: read the
    # token counts in ``usage`` for what a turn actually used.
    cost_usd: float | None = None
    turns: int = 0
    refusals: int = 0
    error: str | None = None
    usage: Mapping[str, int] | None = None


class ToolPolicy:
    """The decision before a tool runs and the record after it, for one turn.

    ``confine`` is for an agent on a host rather than in its own container: see
    airlock.runner.sandbox. It is checked first, then the posture's own guard.
    """

    def __init__(
        self,
        mode: str,
        workdir: Path | None,
        *,
        mcp_allowed: frozenset[str] = frozenset(),
        record: Record | None = None,
        confine: bool = False,
        private: tuple[Path, ...] = (),
    ) -> None:
        if confine and workdir is None:
            raise ValueError("a confined policy needs the working directory it confines to")
        self.mode = mode
        self.workdir = workdir
        self.mcp_allowed = mcp_allowed
        self.record = record
        self.confine = confine
        self.private = private
        self.refusals = 0
        self.calls = 0

    def _write(self, kind: str, **data: Any) -> None:
        if self.record is not None:
            self.record(kind, **data)

    def before(self, tool: str, tool_input: Mapping[str, Any]) -> str | None:
        data = dict(tool_input)
        decision: tuple[str, str] | None = None
        if self.confine and self.workdir is not None:
            reason = confine_reason(tool, data, self.workdir)
            if reason is not None:
                decision = ("sandbox", f"sandbox: {reason}")
        if decision is None:
            reason = private_reason(tool, data, self.private, self.workdir)
            if reason is not None:
                decision = ("private", reason)
        if decision is None:
            decision = deny_reason(tool, data, mode=self.mode, workdir=self.workdir, mcp_allowed=self.mcp_allowed)
        detail, _ = redact(tool_detail(tool_input))
        if decision is not None:
            guard, reason = decision
            self.refusals += 1
            self._write("tool.refused", tool=tool, detail=detail, guard=guard, reason=reason)
            return reason
        self.calls += 1
        self._write("tool.call", tool=tool, detail=detail)
        return None

    def after(self, tool: str, tool_input: Mapping[str, Any], output: str, *, is_error: bool = False) -> None:
        clean, flags = redact(output)
        self._write(
            "tool.result",
            tool=tool,
            detail=redact(tool_detail(tool_input))[0],
            error=is_error,
            output_sha256=sha256_hex(output.encode("utf-8", "replace")),
            tail=clean[-2000:],
            redacted=flags,
        )


def tool_detail(tool_input: Mapping[str, Any] | Any) -> str:
    """The one line that says what a tool call did: the command, the path, or the arguments."""
    if not isinstance(tool_input, Mapping):
        return str(tool_input)[:500]
    for key in ("command", "file_path", "path", "pattern", "url", "query", "question"):
        if tool_input.get(key):
            return str(tool_input[key])[:500]
    return json.dumps(tool_input, ensure_ascii=False, sort_keys=True, default=str)[:500]


class Engine(Protocol):
    async def run(self, request: EngineRequest, policy: ToolPolicy) -> EngineResult: ...


# ---------------------------------------------------------------------- stub


@dataclass
class StubTurn:
    """What a scripted turn does: consult, call tools, then say something."""

    text: str | Callable[[StubTranscript], str] = ""
    consults: Sequence[tuple[str, str]] = ()
    tools: Sequence[tuple[str, Mapping[str, Any]]] = ()
    error: str | None = None


@dataclass
class StubTranscript:
    answers: list[str] = field(default_factory=list)
    outputs: list[tuple[str, str | None]] = field(default_factory=list)


Script = Callable[[EngineRequest], StubTurn | Awaitable[StubTurn]]


class StubEngine:
    """A deterministic engine for tests and the demo. It never calls a model.

    Tool calls go through the policy exactly as a real run's would. A ``Bash``
    call that the policy allows is executed only when ``execute_bash`` is set;
    otherwise its output is a placeholder. Nothing else is ever executed.
    """

    def __init__(self, script: Script, *, execute_bash: bool = False) -> None:
        self.script = script
        self.execute_bash = execute_bash
        self.requests: list[EngineRequest] = []

    async def run(self, request: EngineRequest, policy: ToolPolicy) -> EngineResult:
        self.requests.append(request)
        turn = self.script(request)
        if inspect.isawaitable(turn):
            turn = await turn
        assert isinstance(turn, StubTurn)
        transcript = StubTranscript()
        for to, question in turn.consults:
            if request.consult is None:
                transcript.answers.append("consult is not available in this turn")
                continue
            if policy.before(CONSULT_TOOL, {"to": to, "question": question}) is not None:
                transcript.answers.append("refused")
                continue
            answer = await request.consult(to, question)
            policy.after(CONSULT_TOOL, {"to": to, "question": question}, answer)
            transcript.answers.append(answer)
        for tool, tool_input in turn.tools:
            refused = policy.before(tool, tool_input)
            if refused is not None:
                transcript.outputs.append((tool, None))
                continue
            output = await self._execute(tool, tool_input, request.workdir)
            policy.after(tool, tool_input, output)
            transcript.outputs.append((tool, output))
        text = turn.text(transcript) if callable(turn.text) else turn.text
        return EngineResult(
            text=text,
            session=f"stub-{len(self.requests)}",
            cost_usd=0.0,
            turns=1 + len(turn.tools) + len(turn.consults),
            refusals=policy.refusals,
            error=turn.error,
        )

    async def _execute(self, tool: str, tool_input: Mapping[str, Any], workdir: Path) -> str:
        if tool != "Bash" or not self.execute_bash:
            return f"(stub: {tool} not executed)"
        process = await asyncio.create_subprocess_exec(
            "/bin/sh",
            "-c",
            str(tool_input.get("command") or ""),
            cwd=str(workdir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out, _ = await asyncio.wait_for(process.communicate(), timeout=60)
        except TimeoutError:
            process.kill()
            return "(timed out)"
        return out.decode("utf-8", "replace")
