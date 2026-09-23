"""The Claude Agent SDK behind the engine seam. Optional: ``pip install 'airlock[claude]'``.

The SDK brings the loop, the built-in tools and the MCP client. This module
only configures a session: every tool call goes through the ``ToolPolicy`` in a
PreToolUse hook (matched on every tool, so the gate never depends on how a
matcher pattern is read), and every result is recorded in a PostToolUse hook.
``permission_mode="bypassPermissions"`` because nobody is there to answer a
prompt — the boundary is the hook plus the credentials the container holds.

Consulting another investigator is one in-process MCP tool, present only when
the control plane says this profile may consult somebody.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import json
import logging
import os
from collections.abc import Mapping, Sequence
from typing import Any

from airlock.runner.engine import CONSULT_TOOL, EngineRequest, EngineResult, ToolPolicy
from airlock.runner.gate import refusal

logger = logging.getLogger("airlock.claude")

BUILTIN_TOOLS = ("Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebSearch", "WebFetch", "TodoWrite")
INTERRUPT_GRACE_SECONDS = 30.0

# What the CLI subprocess gets on top of the environment it inherits. The SDK
# passes this process's whole environment through, so a variable is REMOVED by
# setting it to "" here.
CLI_DEFAULTS = {
    # Model calls go to the configured gateway; nothing else leaves (no
    # telemetry, error reports or update checks).
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    # One hung command must not hold the whole turn.
    "BASH_DEFAULT_TIMEOUT_MS": "120000",
    "BASH_MAX_TIMEOUT_MS": "600000",
}
_SECRET_MARKERS = ("SECRET", "TOKEN", "PASSWORD", "PASSWD", "KEY")


def withheld(environ: Mapping[str, str]) -> dict[str, str]:
    """airlock's own secrets, blanked for the agent: with the node's signing secret a
    shell step could post as this profile, and anything it can read it can send."""
    return {name: "" for name in environ if name.startswith("AIRLOCK_") and any(m in name for m in _SECRET_MARKERS)}


def _response_text(response: Any) -> tuple[str, bool]:
    if isinstance(response, dict):
        is_error = bool(response.get("is_error"))
        for key in ("stdout", "output", "content", "result"):
            if key in response:
                value = response[key]
                text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
                stderr = response.get("stderr")
                return (text + (f"\n{stderr}" if stderr else "")), is_error
        return json.dumps(response, ensure_ascii=False, default=str), is_error
    return str(response or ""), False


class ClaudeEngine:
    """``tools`` is the built-in toolset the model is shown at all; the policy still decides each call."""

    def __init__(
        self,
        *,
        model: str | None = None,
        tools: Sequence[str] = BUILTIN_TOOLS,
        env: Mapping[str, str] | None = None,
        max_budget_usd: float | None = None,
    ) -> None:
        self.model = model
        self.tools = tuple(tools)
        self.env = dict(env or {})
        self.max_budget_usd = max_budget_usd

    def cli_env(self) -> dict[str, str]:
        return {**CLI_DEFAULTS, **withheld(os.environ), **self.env}

    async def run(self, request: EngineRequest, policy: ToolPolicy) -> EngineResult:
        from claude_agent_sdk import (
            AssistantMessage,
            ClaudeAgentOptions,
            ClaudeSDKClient,
            HookMatcher,
            ResultMessage,
            TextBlock,
            create_sdk_mcp_server,
            tool,
        )

        async def pre_tool(input_data: dict[str, Any], tool_use_id: str | None, context: Any) -> dict[str, Any]:
            reason = policy.before(str(input_data.get("tool_name") or ""), dict(input_data.get("tool_input") or {}))
            return refusal(reason) if reason is not None else {}

        async def post_tool(input_data: dict[str, Any], tool_use_id: str | None, context: Any) -> dict[str, Any]:
            text, is_error = _response_text(input_data.get("tool_response"))
            policy.after(
                str(input_data.get("tool_name") or ""),
                dict(input_data.get("tool_input") or {}),
                text,
                is_error=is_error,
            )
            return {}

        mcp_servers: dict[str, Any] = {}
        allowed = [*self.tools, *sorted(request.mcp_allowed)]
        if request.consult is not None and request.consultable:
            ask = request.consult

            @tool(
                "consult",
                "Ask another investigator profile one question and get its answer. "
                f"You may ask: {', '.join(request.consultable)}. Say what you already know and exactly what you need.",
                {"to": str, "question": str},
            )
            async def consult_tool(args: dict[str, Any]) -> dict[str, Any]:
                answer = await ask(str(args.get("to") or ""), str(args.get("question") or ""))
                return {"content": [{"type": "text", "text": answer}]}

            mcp_servers["airlock"] = create_sdk_mcp_server(name="airlock", version="1.0.0", tools=[consult_tool])
            allowed.append(CONSULT_TOOL)

        stderr_tail: collections.deque[str] = collections.deque(maxlen=20)
        options = ClaudeAgentOptions(
            cwd=str(request.workdir),
            model=self.model,
            permission_mode="bypassPermissions",
            tools=list(self.tools),
            allowed_tools=allowed,
            env=self.cli_env(),
            max_budget_usd=self.max_budget_usd,
            stderr=stderr_tail.append,
            max_turns=request.max_turns,
            system_prompt={"type": "preset", "preset": "claude_code", "append": request.system},
            # Nothing from the user's or the project's settings: what steers a run
            # is this request, not a file somebody left in the workdir.
            setting_sources=[],
            mcp_servers=mcp_servers,
            hooks={
                "PreToolUse": [HookMatcher(matcher=None, hooks=[pre_tool])],
                "PostToolUse": [HookMatcher(matcher=None, hooks=[post_tool])],
            },
            resume=request.session,
        )

        last_text, turns, result = "", 0, None
        client = ClaudeSDKClient(options=options)

        async def consume() -> None:
            nonlocal last_text, turns, result
            async for message in client.receive_response():
                turns += 1
                if isinstance(message, AssistantMessage):
                    parts = [block.text for block in message.content if isinstance(block, TextBlock) and block.text]
                    if parts:
                        last_text = "\n".join(parts)
                elif isinstance(message, ResultMessage):
                    result = message

        error: str | None = None

        def with_stderr(message: str) -> str:
            tail = " | ".join(line.strip() for line in stderr_tail if line.strip())[-600:]
            return f"{message}; cli stderr: {tail}" if tail else message

        try:
            await client.connect()
            await client.query(request.prompt)
            try:
                await asyncio.wait_for(consume(), timeout=request.timeout_seconds)
            except TimeoutError:
                # Ask the turn to wind down rather than killing it, so the result
                # message (and with it the cost) still arrives.
                error = f"stopped after {request.timeout_seconds:.0f}s"
                with contextlib.suppress(Exception):
                    await client.interrupt()
                    await asyncio.wait_for(consume(), timeout=INTERRUPT_GRACE_SECONDS)
        except Exception as exc:  # noqa: BLE001 — the CLI failing is an engine error with its own words attached
            error = with_stderr(f"{type(exc).__name__}: {exc}"[:400])
        finally:
            with contextlib.suppress(Exception):
                await client.disconnect()

        if result is None:
            return EngineResult(
                text=last_text,
                turns=turns,
                refusals=policy.refusals,
                error=error or with_stderr("the engine produced no result"),
            )
        text = str(getattr(result, "result", None) or last_text or "").strip()
        if getattr(result, "is_error", False) and error is None:
            reason = getattr(result, "subtype", "") or "the engine reported an error"
            status = getattr(result, "api_error_status", None)
            error = f"{reason} (HTTP {status})" if status else str(reason)
        return EngineResult(
            text=text,
            session=getattr(result, "session_id", None),
            cost_usd=getattr(result, "total_cost_usd", None),
            turns=int(getattr(result, "num_turns", None) or turns),
            refusals=policy.refusals,
            error=error,
            usage=token_counts(getattr(result, "usage", None)),
        )


def token_counts(usage: Any) -> dict[str, int] | None:
    """The integer counters of a usage block — tokens in, out, cached — and nothing else."""
    if not isinstance(usage, Mapping):
        return None
    return {k: int(v) for k, v in usage.items() if isinstance(v, int | float) and not isinstance(v, bool)} or None
