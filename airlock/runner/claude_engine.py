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
import contextlib
import json
import logging
from typing import Any

from airlock.runner.engine import CONSULT_TOOL, EngineRequest, EngineResult, ToolPolicy
from airlock.runner.gate import refusal

logger = logging.getLogger("airlock.claude")

BUILTIN_TOOLS = ("Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebSearch", "WebFetch", "TodoWrite")
INTERRUPT_GRACE_SECONDS = 30.0


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
    def __init__(self, *, model: str | None = None, extra_tools: tuple[str, ...] = ()) -> None:
        self.model = model
        self.extra_tools = extra_tools

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
        allowed = [*BUILTIN_TOOLS, *self.extra_tools, *sorted(request.mcp_allowed)]
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

        options = ClaudeAgentOptions(
            cwd=str(request.workdir),
            model=self.model,
            permission_mode="bypassPermissions",
            allowed_tools=allowed,
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
        finally:
            with contextlib.suppress(Exception):
                await client.disconnect()

        if result is None:
            return EngineResult(
                text=last_text, turns=turns, refusals=policy.refusals, error=error or "the engine produced no result"
            )
        text = str(getattr(result, "result", None) or last_text or "").strip()
        if getattr(result, "is_error", False) and error is None:
            error = str(getattr(result, "subtype", "") or "the engine reported an error")
        return EngineResult(
            text=text,
            session=getattr(result, "session_id", None),
            cost_usd=getattr(result, "total_cost_usd", None),
            turns=turns,
            refusals=policy.refusals,
            error=error,
        )
