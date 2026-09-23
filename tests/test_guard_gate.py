from __future__ import annotations

from pathlib import Path

import pytest

from airlock.runner.gate import deny_reason, redact, secret_kinds
from airlock.runner.guard import DANGER_ONLY, READONLY, bash_deny_reason


@pytest.mark.parametrize(
    "command",
    [
        "kubectl delete pod api-1",
        "kubectl -n prod scale deploy/api --replicas=0",
        "aws ec2 terminate-instances --instance-ids i-1",
        "helm upgrade api ./chart",
        "V=1 git push origin main",
    ],
)
def test_readonly_refuses_changes_to_systems(command: str) -> None:
    assert bash_deny_reason(command, READONLY) is not None


def test_readonly_leaves_the_containers_own_scratch_alone() -> None:
    # The investigator's filesystem is its own disposable container; what it may
    # not change is what its credentials reach.
    assert bash_deny_reason("rm -rf ./scratch", READONLY) is None


@pytest.mark.parametrize(
    "command",
    ["kubectl get pods -A", "aws ec2 describe-instances", "grep -r timeout /etc/app", "cat /var/log/app.log"],
)
def test_readonly_allows_reading(command: str) -> None:
    assert bash_deny_reason(command, READONLY) is None


def test_danger_only_allows_ordinary_changes_but_not_catastrophes() -> None:
    assert bash_deny_reason("kubectl -n prod rollout restart deploy/api", DANGER_ONLY) is None
    assert bash_deny_reason("rm -rf /", DANGER_ONLY) is not None
    assert bash_deny_reason("kubectl delete namespace prod", DANGER_ONLY) is not None


def test_gate_protects_the_files_that_steer_the_next_run(tmp_path: Path) -> None:
    for tool, data in [
        ("Write", {"file_path": str(tmp_path / "CLAUDE.md"), "content": "x"}),
        ("Edit", {"file_path": str(tmp_path / ".airlock" / "sessions.json")}),
        ("Bash", {"command": f"echo x >> {tmp_path}/AGENTS.md"}),
        ("Bash", {"command": "printf x | tee .claude/settings.json"}),
    ]:
        decision = deny_reason(tool, data, mode=DANGER_ONLY, workdir=tmp_path)
        assert decision is not None and decision[0] == "input", (tool, data)
    assert deny_reason("Write", {"file_path": str(tmp_path / "notes.md")}, workdir=tmp_path) is None


def test_gate_closes_mcp_tools_by_default() -> None:
    assert deny_reason("mcp__jira__create_issue", {})[0] == "mcp"  # type: ignore[index]
    assert deny_reason("mcp__jira__search", {}, mcp_allowed=frozenset({"mcp__jira__search"})) is None
    assert deny_reason("mcp__jira__search", {}, mcp_allowed=frozenset({"mcp__jira__*"})) is None


def test_redact_names_the_kind_never_the_value() -> None:
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    text, kinds = redact(f"the key is {key} ok")
    assert key not in text and kinds == ["aws access key id"]
    assert secret_kinds("nothing secret here, password=hunter2") == []
