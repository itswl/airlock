"""Confinement for a node on a host: only its working directory, only read commands."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from airlock.runner.claude_engine import CLI_DEFAULTS, ClaudeEngine, withheld
from airlock.runner.engine import CONSULT_TOOL, ToolPolicy
from airlock.runner.guard import READONLY
from airlock.runner.sandbox import confine_reason, inside, shell_reason


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "api.log").write_text("pool exhausted\n")
    (tmp_path / ".airlock").mkdir()
    return tmp_path


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "cat logs/api.log",
        "grep -rn 'pool exhausted' .",
        "grep -c pool logs/api.log | wc -l",
        "find . -name '*.log' -type f",
        "head -n 20 logs/api.log && tail -5 logs/api.log",
        "jq '.items[] | .name' data.json",
        "sort logs/api.log | uniq -c",
        "grep -e 'v1/pay' logs/api.log",
        "echo 'cost is $5 total'",
    ],
)
def test_reading_inside_the_working_directory_is_allowed(root: Path, command: str) -> None:
    assert shell_reason(command, root) is None, command


@pytest.mark.parametrize(
    ("command", "because"),
    [
        ("cat ~/.aws/credentials", "outside"),
        ("cat /etc/hosts", "outside"),
        ("ls ..", "outside"),
        ("grep -r key ../..", "outside"),
        ("grep --file=/etc/passwd x logs/api.log", "outside"),
        ("grep -f /etc/passwd logs/api.log", "outside"),
        ("grep '/v1/pay' logs/api.log", "must not start with /"),
        ("find / -name id_rsa", "outside"),
        ("cat logs/../../secret", "outside"),
        ("echo $HOME", "substitution"),
        ('echo "$(whoami)"', "expansion inside double quotes"),
        ("cat logs/api.log > copy.txt", "redirection"),
        ("cat logs/api.log 2>&1", "redirection"),
        ("sleep 100 &", "background job"),
        ("kubectl get pods", "not one of the read commands"),
        ("sed -n p logs/api.log", "not one of the read commands"),
        ("awk '{print $1}' logs/api.log", "not one of the read commands"),
        ("python3 -c 'print(1)'", "not one of the read commands"),
        ("env", "not one of the read commands"),
        ("find . -name x -delete", "not act on what it finds"),
        ("sort -o out.txt logs/api.log", "may not write"),
        ("uniq logs/api.log out.txt", "may not write"),
        ("cat .airlock/sessions.json", "own state"),
        ("cat 'unclosed", "unclosed quote"),
        ("ls; rm -rf .", "not one of the read commands"),
    ],
)
def test_everything_else_is_refused_with_a_reason(root: Path, command: str, because: str) -> None:
    reason = shell_reason(command, root)
    assert reason is not None and because in reason, (command, reason)


def test_file_tools_stay_inside(root: Path) -> None:
    assert confine_reason("Read", {"file_path": str(root / "logs" / "api.log")}, root) is None
    assert confine_reason("Read", {"file_path": "logs/api.log"}, root) is None
    assert "outside" in str(confine_reason("Read", {"file_path": "/etc/hosts"}, root))
    assert "outside" in str(confine_reason("Grep", {"pattern": "key", "path": str(Path.home())}, root))
    assert confine_reason("Grep", {"pattern": "pool"}, root) is None
    assert confine_reason("Glob", {"pattern": "**/*.log"}, root) is None
    assert "outside" in str(confine_reason("Glob", {"pattern": "/Users/*/.ssh/*"}, root))
    assert "outside" in str(confine_reason("Glob", {"pattern": "../../**/*"}, root))
    assert "not available" in str(confine_reason("WebFetch", {"url": "https://example.invalid"}, root))
    assert "not available" in str(confine_reason("Task", {"prompt": "x"}, root))
    assert confine_reason(CONSULT_TOOL, {"to": "code", "question": "?"}, root) is None


def test_symlinks_out_of_the_directory_do_not_count_as_inside(
    root: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    outside = tmp_path_factory.mktemp("elsewhere") / "secret.txt"
    outside.write_text("x")
    (root / "link.txt").symlink_to(outside)
    assert not inside(root, "link.txt")
    assert "outside" in str(shell_reason("cat ./link.txt", root))


def test_the_policy_checks_confinement_first_and_records_it(root: Path) -> None:
    records: list[tuple[str, dict]] = []
    policy = ToolPolicy(READONLY, root, confine=True, record=lambda kind, **d: records.append((kind, d)))
    assert policy.before("Bash", {"command": "cat /etc/hosts"}) is not None
    assert policy.before("Bash", {"command": "cat logs/api.log"}) is None
    assert policy.before("Bash", {"command": "kubectl -n prod get pods"}) is not None  # not a read command here
    assert [(k, d.get("guard")) for k, d in records] == [
        ("tool.refused", "sandbox"),
        ("tool.call", None),
        ("tool.refused", "sandbox"),
    ]
    unconfined = ToolPolicy(READONLY, root)
    assert unconfined.before("Bash", {"command": "kubectl -n prod get pods"}) is None
    with pytest.raises(ValueError):
        ToolPolicy(READONLY, None, confine=True)


def test_the_cli_environment_withholds_airlock_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AIRLOCK_SECRET", "s")
    monkeypatch.setenv("AIRLOCK_LAUNCHER_SECRET", "s")
    monkeypatch.setenv("AIRLOCK_PROFILE", "infra")
    blanked = withheld(os.environ)
    assert blanked["AIRLOCK_SECRET"] == "" and blanked["AIRLOCK_LAUNCHER_SECRET"] == ""
    assert "AIRLOCK_PROFILE" not in blanked
    env = ClaudeEngine(env={"ANTHROPIC_MODEL": "m"}).cli_env()
    assert env["AIRLOCK_SECRET"] == "" and env["ANTHROPIC_MODEL"] == "m"
    assert env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == CLI_DEFAULTS["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"]
