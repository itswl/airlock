"""Repositories a worker may change: a fresh clone per run, and the change computed outside the worker's reach."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest

from airlock.config import ConfigError, WorkerProfile, load_launcher
from airlock.launcher.runtime import GroupSpec, docker_argv
from airlock.launcher.workspace import WorkspaceError, changes, prepare
from airlock.plans import groups, parse_plan, validate_plan
from airlock.runner.executor import engine_env, task_prompt
from airlock.runner.recorder import read_lines, verify_lines
from tests.conftest import plan_doc
from tests.test_launcher import approval_for, make_launcher

GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def git(cwd: Path, *argv: str) -> str:
    return subprocess.run(["git", *argv], cwd=cwd, env=GIT_ENV, capture_output=True, text=True, check=True).stdout


def mirror(tmp_path: Path) -> Path:
    repo = tmp_path / "mirror"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    (repo / "README.md").write_text("demo\n")
    (repo / "old.txt").write_text("to be removed\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "start")
    return repo


def test_a_run_gets_its_own_clone_and_nothing_it_commits_reaches_the_mirror(tmp_path: Path) -> None:
    source = mirror(tmp_path)
    start = git(source, "rev-parse", "HEAD").strip()
    ws = prepare("demo", source, tmp_path / "run" / "workspace")
    assert ws.start == start and git(ws.path, "remote").strip() == ""
    (ws.path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    git(ws.path, "commit", "-qam", "fix")
    assert git(source, "rev-parse", "HEAD").strip() == start  # the mirror never moved
    with pytest.raises(WorkspaceError, match="already exists"):
        prepare("demo", source, ws.path)


def test_the_change_is_the_end_state_against_the_mirror_and_applies_as_a_patch(tmp_path: Path) -> None:
    source = mirror(tmp_path)
    ws = prepare("demo", source, tmp_path / "run" / "workspace")
    (ws.path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (ws.path / "test_calc.py").write_text("from calc import add\n\nassert add(2, 2) == 4\n")
    (ws.path / "old.txt").unlink()
    (ws.path / "blob.bin").write_bytes(b"\x00\x01\x02")
    git(ws.path, "add", "-A")
    git(ws.path, "commit", "-qm", "fix and test")
    (ws.path / "README.md").write_text("demo\nnot committed, still part of the change\n")
    found = changes(ws, tmp_path / "run" / "group-1.patch")
    assert found["files"] == ["README.md", "blob.bin", "calc.py", "old.txt", "test_calc.py"]
    assert found["insertions"] == 5 and found["deletions"] == 2
    patch = (tmp_path / "run" / "group-1.patch").read_text()
    assert "Binary files /dev/null and b/blob.bin differ" in patch
    # The text part of it is a patch git takes: applied to a fresh clone, it gives the same files.
    check = tmp_path / "check"
    git(tmp_path, "clone", "-q", str(source), str(check))
    parts = re.split(r"(?m)^(?=diff --git )", patch)
    (tmp_path / "text.patch").write_text("".join(p for p in parts if p and not p.startswith("diff --git a/blob.bin ")))
    git(check, "apply", str(tmp_path / "text.patch"))
    for name in ("calc.py", "test_calc.py", "README.md"):
        assert (check / name).read_text() == (ws.path / name).read_text()
    assert not (check / "old.txt").exists()


def test_the_launcher_never_runs_git_in_the_workspace_and_never_reads_through_a_link(tmp_path: Path) -> None:
    source = mirror(tmp_path)
    ws = prepare("demo", source, tmp_path / "run" / "workspace")
    marker = tmp_path / "ran"
    # What a worker could leave behind for whoever runs git here next.
    git(ws.path, "config", "core.fsmonitor", f"touch {marker}")
    git(ws.path, "config", "filter.x.clean", f"touch {marker}")
    (ws.path / ".gitattributes").write_text("* filter=x\n")
    secret = tmp_path / "launcher-secret.txt"
    secret.write_text("the launcher's own file\n")
    (ws.path / "peek").symlink_to(secret)
    if hasattr(os, "mkfifo"):
        os.mkfifo(ws.path / "pipe")  # would block a reader that opened it
    found = changes(ws, tmp_path / "run" / "group-1.patch")
    patch = (tmp_path / "run" / "group-1.patch").read_text()
    assert not marker.exists()
    assert "the launcher's own file" not in patch
    assert f"# peek: absent -> symbolic link to {secret}" in patch
    assert "pipe" not in found["files"] and ".gitattributes" in found["files"]


def test_steps_on_a_worker_with_repos_name_one_and_each_repository_is_its_own_group() -> None:
    workers = {
        "code": WorkerProfile(name="code", modes=("task",), allowed_permissions=("repo:commit",), repos={"a": "/r/a"}),
        "ops": WorkerProfile(name="ops", command_allowlist=("true",), allowed_permissions=("svc:restart",)),
    }
    steps = [
        {"worker": "code", "target": "repo:a", "task": "one"},
        {"worker": "code", "target": "repo:a", "task": "two"},
        {"worker": "code", "target": "repo:b", "task": "three"},
        {"worker": "code", "target": "demo/api", "task": "four"},
    ]
    plan = parse_plan(plan_doc(permissions={"code": ["repo:commit"]}, steps=steps))
    errors = validate_plan(plan, workers)
    assert errors == [
        "step 3: worker code changes repositories, so its target is one of repo:a",
        "step 4: worker code changes repositories, so its target is one of repo:a",
    ]
    assert [(g["repo"], [s["index"] for s in g["steps"]]) for g in groups(plan)] == [
        ("repo:a", [1, 2]),
        ("repo:b", [3]),
        (None, [4]),
    ]


@pytest.mark.parametrize(
    ("worker", "message"),
    [
        ({"repos": {"a b": "/r"}}, "repository name 'a b'"),
        ({"repos": {"a": "relative/path"}}, "must be an absolute path"),
        ({"repos": {"a": "/r"}, "workspace_dir": "/w"}, "two answers to one question"),
    ],
)
def test_a_worker_s_repositories_are_checked_at_load(
    config_dict: dict[str, Any], env: dict[str, str], worker: dict[str, Any], message: str
) -> None:
    config = {**config_dict, "workers": [{"name": "code", "modes": ["task"], **worker}]}
    with pytest.raises(ConfigError, match=message):
        load_launcher(config, env)


def test_the_container_mounts_this_run_s_clone_and_the_prompt_says_so(tmp_path: Path) -> None:
    worker = WorkerProfile(name="code", modes=("task",), repos={"demo": "/r"}, instructions="Commit each step.")
    step = {"index": 1, "worker": "code", "target": "repo:demo", "task": "fix it"}
    spec = GroupSpec("ap1", "w1", "h" * 64, 1, worker, [step], [], tmp_path / "out", workspace=tmp_path / "ws")
    argv = docker_argv("docker", spec)
    assert f"{(tmp_path / 'ws').resolve()}:/workspace:rw" in argv
    assert "GIT_AUTHOR_EMAIL=code+ap1@airlock.invalid" in argv
    prompt = task_prompt(step, spec.payload(workdir="/workspace", out_dir="/airlock/out"))
    assert "repo:demo is checked out in your working directory" in prompt and "Commit each step." in prompt


def test_a_task_worker_finds_its_model_settings_with_its_credentials(tmp_path: Path) -> None:
    (tmp_path / "engine.env").write_text("# model\nANTHROPIC_BASE_URL=https://model.invalid\nAIRLOCK_MODEL='m-1'\n")
    assert engine_env(str(tmp_path)) == {"ANTHROPIC_BASE_URL": "https://model.invalid", "AIRLOCK_MODEL": "m-1"}
    assert engine_env(None) == {} and engine_env(str(tmp_path / "none")) == {}


@pytest.mark.anyio
async def test_the_launcher_keeps_the_change_and_reports_it(
    config_dict: dict[str, Any], env: dict[str, str], tmp_path: Path
) -> None:
    source = mirror(tmp_path)
    start = git(source, "rev-parse", "HEAD").strip()
    workers = [
        {"name": "code", "modes": ["task"], "repos": {"demo": str(source)}, "allowed_permissions": ["repo:commit"]}
    ]
    launcher, control = make_launcher(config_dict, env, workers=workers)
    task = "$ printf 'def add(a, b):\\n    return a + b\\n' > calc.py\n$ git commit -qam 'fix add'"
    plan = plan_doc(
        permissions={"code": ["repo:commit"]}, steps=[{"worker": "code", "target": "repo:demo", "task": task}]
    )
    assert launcher.accept(approval_for(plan)).status == 202
    await launcher.drain()
    result = control.results[0]
    assert result["status"] == "done", result
    workspace = result["groups"][0]["workspace"]
    assert workspace["repo"] == "demo" and workspace["start"] == start and workspace["files"] == ["calc.py"]
    assert "+    return a + b" in workspace["patch"] and "-    return a - b" in workspace["patch"]
    run_dir = Path(launcher.config.runs_dir) / "ap1"
    own = read_lines(run_dir / "launcher.jsonl")
    kinds = [line["kind"] for line in own]
    assert kinds[:3] == ["launch.accepted", "workspace.prepared", "group.started"] and "workspace.changes" in kinds
    assert verify_lines(own)["intact"]
    assert (run_dir / "group-1.patch").read_text() == workspace["patch"]
    assert git(source, "rev-parse", "HEAD").strip() == start
    await launcher.close()


@pytest.mark.anyio
async def test_a_repository_that_cannot_be_cloned_fails_the_run_before_anything_starts(
    config_dict: dict[str, Any], env: dict[str, str], tmp_path: Path
) -> None:
    workers = [
        {"name": "code", "modes": ["task"], "repos": {"demo": str(tmp_path / "gone")}, "allowed_permissions": ["x"]}
    ]
    launcher, control = make_launcher(config_dict, env, workers=workers)
    plan = plan_doc(permissions={"code": ["x"]}, steps=[{"worker": "code", "target": "repo:demo", "task": "$ true"}])
    launcher.accept(approval_for(plan))
    await launcher.drain()
    result = control.results[0]
    assert result["status"] == "failed" and "could not be prepared" in result["reason"]
    kinds = [line["kind"] for line in read_lines(Path(launcher.config.runs_dir) / "ap1" / "launcher.jsonl")]
    assert "group.started" not in kinds and "workspace.failed" in kinds
    await launcher.close()
