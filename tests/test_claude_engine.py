"""The Claude engine's wiring, against a stand-in for the SDK: the real SDK is optional and never called in tests."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

from airlock.runner.claude_engine import ClaudeEngine
from airlock.runner.engine import CONSULT_TOOL, EngineRequest, ToolPolicy
from airlock.runner.guard import READONLY

pytestmark = pytest.mark.anyio


def fake_sdk(seen: dict[str, Any]) -> types.ModuleType:
    sdk = types.ModuleType("claude_agent_sdk")

    class ClaudeAgentOptions:
        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

    class HookMatcher:
        def __init__(self, matcher: str | None = None, hooks: list[Any] | None = None) -> None:
            self.matcher, self.hooks = matcher, hooks or []

    class TextBlock:
        def __init__(self, text: str) -> None:
            self.text = text

    class AssistantMessage:
        def __init__(self, content: list[Any]) -> None:
            self.content = content

    class ResultMessage:
        def __init__(self, **kwargs: Any) -> None:
            self.__dict__.update(kwargs)

    class Tool:
        def __init__(self, name: str, handler: Any) -> None:
            self.name, self.handler = name, handler

    def tool(name: str, description: str, schema: Any):  # noqa: ANN202
        seen["tool_description"] = description
        return lambda handler: Tool(name, handler)

    def create_sdk_mcp_server(name: str, version: str, tools: list[Any]) -> dict[str, Any]:
        return {"name": name, "tools": tools}

    class ClaudeSDKClient:
        def __init__(self, options: Any) -> None:
            self.options = options
            seen["options"] = options

        async def connect(self) -> None:
            seen["connected"] = True

        async def query(self, prompt: str) -> None:
            seen["prompt"] = prompt

        async def receive_response(self):  # noqa: ANN202
            pre = self.options.hooks["PreToolUse"][0].hooks[0]
            post = self.options.hooks["PostToolUse"][0].hooks[0]
            seen["denied"] = await pre(
                {"tool_name": "Bash", "tool_input": {"command": "kubectl -n prod delete pod api-1"}}, "t1", None
            )
            seen["allowed"] = await pre(
                {"tool_name": "Bash", "tool_input": {"command": "kubectl -n prod get pods"}}, "t2", None
            )
            await post(
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "kubectl -n prod get pods"},
                    "tool_response": {"stdout": "api-1 Running"},
                },
                "t2",
                None,
            )
            consult = self.options.mcp_servers["airlock"]["tools"][0]
            seen["consult_reply"] = await consult.handler({"to": "code", "question": "deploys?"})
            yield AssistantMessage([TextBlock("thinking out loud")])
            yield ResultMessage(result="final report", session_id="sess-9", total_cost_usd=0.42, is_error=False)

        async def interrupt(self) -> None:
            seen["interrupted"] = True

        async def disconnect(self) -> None:
            seen["disconnected"] = True

    for name, value in {
        "ClaudeAgentOptions": ClaudeAgentOptions,
        "ClaudeSDKClient": ClaudeSDKClient,
        "HookMatcher": HookMatcher,
        "AssistantMessage": AssistantMessage,
        "ResultMessage": ResultMessage,
        "TextBlock": TextBlock,
        "tool": tool,
        "create_sdk_mcp_server": create_sdk_mcp_server,
    }.items():
        setattr(sdk, name, value)
    return sdk


async def test_hooks_put_every_tool_call_to_the_policy_and_consult_is_one_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", fake_sdk(seen))
    records: list[tuple[str, dict[str, Any]]] = []

    async def consult(to: str, question: str) -> str:
        return f"{to} answers {question}"

    request = EngineRequest(
        prompt="investigate",
        system="be careful",
        mode=READONLY,
        workdir=tmp_path,
        session="sess-8",
        consult=consult,
        consultable=("code",),
        mcp_allowed=frozenset({CONSULT_TOOL}),
    )
    policy = ToolPolicy(
        READONLY, tmp_path, mcp_allowed=request.mcp_allowed, record=lambda kind, **d: records.append((kind, d))
    )
    result = await ClaudeEngine(model="some-model").run(request, policy)

    options = seen["options"]
    assert options.permission_mode == "bypassPermissions" and options.setting_sources == []
    assert options.resume == "sess-8" and options.model == "some-model" and options.cwd == str(tmp_path)
    assert options.system_prompt == {"type": "preset", "preset": "claude_code", "append": "be careful"}
    assert CONSULT_TOOL in options.allowed_tools and "code" in seen["tool_description"]
    assert seen["denied"]["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "read-only guard" in seen["denied"]["hookSpecificOutput"]["permissionDecisionReason"]
    assert seen["allowed"] == {}
    assert seen["consult_reply"] == {"content": [{"type": "text", "text": "code answers deploys?"}]}
    assert [kind for kind, _ in records] == ["tool.refused", "tool.call", "tool.result"]
    assert records[2][1]["tail"] == "api-1 Running"
    assert (result.text, result.session, result.cost_usd, result.refusals, result.error) == (
        "final report",
        "sess-9",
        0.42,
        1,
        None,
    )
    assert seen["disconnected"]


async def test_no_consult_server_without_somebody_to_consult(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}
    sdk = fake_sdk(seen)

    class Quiet(sdk.ClaudeSDKClient):  # type: ignore[name-defined, misc]
        async def receive_response(self):  # noqa: ANN202
            yield sdk.ResultMessage(result="ok", session_id="s", total_cost_usd=0.0, is_error=False)

    sdk.ClaudeSDKClient = Quiet  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", sdk)
    request = EngineRequest(prompt="p", system="s", mode=READONLY, workdir=tmp_path)
    result = await ClaudeEngine().run(request, ToolPolicy(READONLY, tmp_path))
    assert seen["options"].mcp_servers == {} and CONSULT_TOOL not in seen["options"].allowed_tools
    assert result.text == "ok"
