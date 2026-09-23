"""MCP servers and skills for investigators: the file, its location, the engine options, the gate."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from airlock.runner.claude_engine import ClaudeEngine
from airlock.runner.engine import CONSULT_TOOL, EngineRequest, ToolPolicy
from airlock.runner.guard import READONLY
from airlock.runner.investigator import load_node
from airlock.runner.mcp import McpConfigError, load_mcp_servers, safe_location
from airlock.runner.sandbox import confine_reason
from tests.test_claude_engine import fake_sdk

SERVERS = {
    "mcpServers": {
        "demo": {"command": "python3", "args": ["server.py"]},
        "grafana": {"type": "http", "url": "https://grafana.example.invalid/mcp"},
    }
}


def write(path: Path, data: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path


def test_the_file_is_the_mcp_json_shape(tmp_path: Path) -> None:
    assert set(load_mcp_servers(write(tmp_path / "a.json", SERVERS))) == {"demo", "grafana"}
    assert set(load_mcp_servers(write(tmp_path / "b.json", SERVERS["mcpServers"]))) == {"demo", "grafana"}


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{not json", "not JSON"),
        ("[1, 2]", "expected"),
        ({"mcpServers": {"airlock": {"command": "x"}}}, "airlock's own"),
        ({"mcpServers": {"bad name": {"command": "x"}}}, "must be letters"),
        ({"mcpServers": {"demo": "python3"}}, "must be an object"),
        ({"mcpServers": {"demo": {"args": []}}}, "needs a command"),
        ({"mcpServers": {"demo": {"type": "http"}}}, "needs a url"),
        ({"mcpServers": {"demo": {"type": "ws", "url": "x"}}}, "use one of"),
    ],
)
def test_a_file_that_cannot_be_used_says_why(tmp_path: Path, content: Any, message: str) -> None:
    with pytest.raises(McpConfigError, match=message):
        load_mcp_servers(write(tmp_path / "mcp.json", content))
    with pytest.raises(McpConfigError, match="No such file"):
        load_mcp_servers(tmp_path / "missing.json")


def test_the_file_must_be_somewhere_the_agent_cannot_write(tmp_path: Path) -> None:
    workdir = tmp_path / "work"
    workdir.mkdir()
    assert safe_location(tmp_path / "etc" / "mcp.json", workdir)
    assert safe_location(workdir / ".claude" / "mcp.json", workdir)
    assert not safe_location(workdir / "mcp.json", workdir)
    assert not safe_location(workdir / "sub" / "mcp.json", workdir)

    base = {
        "AIRLOCK_PROFILE": "infra",
        "AIRLOCK_SECRET": "s",
        "AIRLOCK_CONTROL_URL": "http://control",
        "AIRLOCK_WORKDIR": str(workdir),
    }
    with pytest.raises(SystemExit, match="agent can write it"):
        load_node({**base, "AIRLOCK_MCP_CONFIG": str(write(workdir / "mcp.json", SERVERS))})
    with pytest.raises(SystemExit, match="not JSON"):
        load_node({**base, "AIRLOCK_MCP_CONFIG": str(write(tmp_path / "broken.json", "{"))})
    config = load_node(
        {
            **base,
            "AIRLOCK_MCP_CONFIG": str(write(workdir / ".claude" / "mcp.json", SERVERS)),
            "AIRLOCK_SKILLS": "pool, disk ",
        }
    )
    assert config.mcp_config == workdir / ".claude" / "mcp.json" and config.skills == ("pool", "disk")
    assert load_node({**base, "AIRLOCK_SKILLS": "all"}).skills == ("all",)


def quiet_sdk(seen: dict[str, Any]) -> Any:
    sdk = fake_sdk(seen)

    class Quiet(sdk.ClaudeSDKClient):  # type: ignore[name-defined, misc]
        async def receive_response(self):  # noqa: ANN202
            yield sdk.ResultMessage(result="ok", session_id="s", total_cost_usd=0.0, is_error=False, num_turns=1)

    sdk.ClaudeSDKClient = Quiet
    return sdk


@pytest.mark.anyio
async def test_the_engine_passes_the_servers_strictly_and_reads_them_every_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", quiet_sdk(seen))
    config = write(tmp_path / "mcp.json", {"mcpServers": {"demo": {"command": "python3"}}})

    async def ask(to: str, question: str) -> str:
        return "answer"

    engine = ClaudeEngine(mcp_config=config)
    request = EngineRequest(
        prompt="p",
        system="s",
        mode=READONLY,
        workdir=tmp_path,
        consult=ask,
        consultable=("code",),
        mcp_allowed=frozenset({CONSULT_TOOL, "mcp__demo__deploy_history"}),
    )
    await engine.run(request, ToolPolicy(READONLY, tmp_path))
    options = seen["options"]
    assert set(options.mcp_servers) == {"demo", "airlock"} and options.strict_mcp_config is True
    assert "mcp__demo__deploy_history" in options.allowed_tools
    assert options.setting_sources == [] and options.skills is None and "Skill" not in options.tools

    write(
        config,
        {
            "mcpServers": {
                "demo": {"command": "python3"},
                "jira": {"type": "http", "url": "https://jira.example.invalid"},
            }
        },
    )
    await engine.run(request, ToolPolicy(READONLY, tmp_path))
    assert set(seen["options"].mcp_servers) == {"demo", "jira", "airlock"}, "an edit takes effect on the next run"

    write(config, "{")
    seen.clear()
    result = await engine.run(request, ToolPolicy(READONLY, tmp_path))
    assert result.error is not None and result.error.startswith("MCP configuration") and "options" not in seen


@pytest.mark.anyio
async def test_skills_turn_on_project_settings_and_the_skill_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", quiet_sdk(seen))
    request = EngineRequest(prompt="p", system="s", mode=READONLY, workdir=tmp_path)
    await ClaudeEngine(skills="all").run(request, ToolPolicy(READONLY, tmp_path))
    assert seen["options"].skills == "all" and seen["options"].setting_sources == ["project"]
    assert "Skill" in seen["options"].tools
    await ClaudeEngine(skills=["pool-exhaustion"]).run(request, ToolPolicy(READONLY, tmp_path))
    assert seen["options"].skills == ["pool-exhaustion"]


def test_confined_nodes_leave_mcp_tools_to_the_allowlist(tmp_path: Path) -> None:
    assert confine_reason("mcp__demo__deploy_history", {"service": "api"}, tmp_path) is None
    assert confine_reason("Skill", {"skill": "pool-exhaustion"}, tmp_path) is None
    records: list[tuple[str, dict[str, Any]]] = []
    policy = ToolPolicy(
        READONLY,
        tmp_path,
        confine=True,
        mcp_allowed=frozenset({"mcp__demo__deploy_history"}),
        record=lambda kind, **d: records.append((kind, d)),
    )
    assert policy.before("mcp__demo__deploy_history", {"service": "api"}) is None
    refused = policy.before("mcp__demo__restart_service", {"service": "api"})
    assert refused is not None and "not on this profile's MCP allowlist" in refused
    assert [(kind, data.get("guard")) for kind, data in records] == [("tool.call", None), ("tool.refused", "mcp")]
