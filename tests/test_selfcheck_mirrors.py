"""The self-check (alarms once, repeats, says when it recovers) and the mirrors (fresh, clean, no token on a command line)."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from airlock.extras import mirrors
from airlock.extras.mirrors import load_mirrors, sync_all
from airlock.extras.selfcheck import Selfcheck, check_model, check_watcher, load_selfcheck


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_a_failing_check_alarms_once_repeats_and_says_when_it_recovers(tmp_path: Path) -> None:
    config = load_selfcheck(
        {
            "state": str(tmp_path / "state.json"),
            "every_minutes": 5,
            "alarm": {"repeat_minutes": 60},
            "checks": [{"name": "control", "url": "http://control/healthz"}],
        }
    )
    healthy = {"up": False}

    def control(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True}) if healthy["up"] else httpx.Response(503)

    alarms: list[str] = []
    clock = Clock(1_700_000_000.0)
    check = Selfcheck(
        config, client=httpx.Client(transport=httpx.MockTransport(control)), alarm=alarms.append, clock=clock
    )
    for _ in range(3):  # the first failure waits for a second one; then one alarm, not one per tick
        check.tick()
        clock.now += 300
    assert len(alarms) == 1 and "control 不正常：HTTP 503" in alarms[0]
    clock.now += 3600
    check.tick()
    assert len(alarms) == 2  # still failing an hour later: said again
    healthy["up"] = True
    clock.now += 300
    check.tick()
    assert alarms[-1].startswith("✅") and "control 恢复" in alarms[-1]
    clock.now += 300
    check.tick()
    assert len(alarms) == 3


def test_the_watcher_is_late_only_inside_its_hours(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    try:
        status = tmp_path / "status.json"
        monday_10 = datetime(2026, 9, 21, 10, 0, tzinfo=UTC).timestamp()
        schedule = {"every_minutes": 20, "window": "09:30-19:30", "days": "1-5", "tz": ""}
        status.write_text(json.dumps({"tick_at": monday_10 - 3600, "outcome": "quiet", "schedule": schedule}))
        ok, detail = check_watcher(str(status), monday_10)
        assert not ok and "60 分钟没有动静" in detail
        assert check_watcher(str(status), monday_10 + 12 * 3600)[0]  # 22:00: nothing expected
        status.write_text(
            json.dumps({"tick_at": monday_10, "outcome": "error", "error": "engine", "schedule": schedule})
        )
        assert check_watcher(str(status), monday_10 + 60) == (False, "上一轮出错：engine")
        status.write_text(
            json.dumps(
                {"tick_at": monday_10, "outcome": "fired", "failed_deliveries": 1, "error": "503", "schedule": schedule}
            )
        )
        assert "1 条信号没送到" in check_watcher(str(status), monday_10 + 60)[1]
        assert check_watcher(str(tmp_path / "none.json"), monday_10) == (False, "the watcher has written no status yet")
    finally:
        monkeypatch.undo()
        time.tzset()


def test_the_model_check_is_one_token_against_the_configured_gateway() -> None:
    seen: list[dict[str, Any]] = []

    def gateway(request: httpx.Request) -> httpx.Response:
        seen.append({"url": str(request.url), **json.loads(request.content)})
        return httpx.Response(200, json={"content": []})

    env = {"ANTHROPIC_BASE_URL": "https://gw.invalid/anthropic", "ANTHROPIC_AUTH_TOKEN": "k", "AIRLOCK_MODEL": "m"}
    assert check_model(env, httpx.Client(transport=httpx.MockTransport(gateway))) == (True, "the model answers")
    assert seen[0]["url"] == "https://gw.invalid/anthropic/v1/messages" and seen[0]["max_tokens"] == 1
    down = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(502)))
    assert check_model(env, down) == (False, "the model gateway answers HTTP 502")
    assert not check_model({}, down)[0]


def git(cwd: Path, *argv: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@x.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@x.invalid",
        "GIT_CONFIG_GLOBAL": os.devnull,
    }
    return subprocess.run(["git", *argv], cwd=cwd, env=env, capture_output=True, text=True, check=True).stdout.strip()


def test_a_mirror_follows_its_remote_and_is_nobody_s_working_copy(tmp_path: Path) -> None:
    work = tmp_path / "upstream"
    work.mkdir()
    git(work, "init", "-q", "-b", "main")
    (work / "app.py").write_text("v1\n")
    git(work, "add", "-A")
    git(work, "commit", "-qm", "one")
    remote = tmp_path / "remote.git"
    git(tmp_path, "clone", "-q", "--bare", str(work), str(remote))
    config = load_mirrors(
        {
            "root": str(tmp_path / "repos"),
            "repos": [
                {"name": "app", "url": f"file://{remote}"},
                {"name": "gone", "url": f"file://{tmp_path}/nope.git"},
            ],
        }
    )
    first = sync_all(config)
    assert first["app"]["ok"] and first["app"]["branch"] == "main" and not first["gone"]["ok"]
    (work / "app.py").write_text("v2\n")
    git(work, "commit", "-qam", "two")
    git(work, "push", "-q", str(remote), "main")
    mirror = tmp_path / "repos" / "app"
    (mirror / "app.py").write_text("somebody edited the mirror\n")
    (mirror / "stray.txt").write_text("left behind\n")
    second = sync_all(config)
    assert second["app"]["head"] == git(work, "rev-parse", "HEAD")
    assert (mirror / "app.py").read_text() == "v2\n" and not (mirror / "stray.txt").exists()
    status = json.loads((tmp_path / "repos" / ".mirrors-status.json").read_text())
    assert status["repos"]["app"]["ok"] and not status["repos"]["gone"]["ok"]


def test_the_token_is_never_on_a_command_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = load_mirrors(
        {"root": str(tmp_path), "repos": [{"name": "a", "url": "https://x.invalid/a.git"}], "token_env": "T_TOKEN"},
        {"T_TOKEN": "ghp_secret"},
    )
    seen: list[list[str]] = []

    def fake_run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.append(command)
        assert kwargs["env"]["AIRLOCK_MIRRORS_PASSWORD"] == "ghp_secret"
        return subprocess.CompletedProcess(command, 1, "", "fatal: ghp_secret rejected")

    monkeypatch.setattr(mirrors.subprocess, "run", fake_run)
    result = mirrors.sync(config, config.repos[0])
    assert not result["ok"] and "ghp_secret" not in result["error"] and "[token]" in result["error"]
    assert all("ghp_secret" not in part for command in seen for part in command)
