"""The road around everything else: is each piece up, does the model answer, is the watcher's clock still ticking.

    python -m airlock.extras.selfcheck --config selfcheck.yaml [--once]

Three kinds of check, each on its own interval:
- ``url``: a health endpoint answers 2xx, and not ``"ok": false``;
- ``watcher_status``: the watcher's ``status.json``. Inside its working hours it
  must have ticked recently, its last round must not have failed, and no
  delivery may have failed. A watcher that is never triggered looks exactly
  like a quiet afternoon, and this is what tells the two apart;
- ``model``: one one-token call to the configured gateway. A dead gateway
  otherwise shows only as a pile of failed investigations.

A check that fails twice in a row alarms once. It alarms again every
``repeat_minutes`` while it stays failing, and once more when it recovers. The
alarm goes out through its own custom bot webhook, never through the chat
adapter, which may be the thing that is down.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml

from airlock.extras.feishu.lark import LarkError, Webhook
from airlock.extras.settings import SettingsError, value
from airlock.extras.watch.config import Schedule
from airlock.extras.watch.scan import in_window, write_atomically

logger = logging.getLogger("airlock.selfcheck")
FAILS_BEFORE_ALARM = 2
START_AFTER_SECONDS = 60


@dataclass(frozen=True)
class Check:
    name: str
    kind: str  # url | watcher_status | model
    target: str
    every_minutes: int


@dataclass(frozen=True)
class SelfcheckConfig:
    checks: tuple[Check, ...]
    state: Path
    every_minutes: int
    alarm_url: str
    alarm_secret: str
    repeat_minutes: int
    tz: str


def load_selfcheck(source: str | Path | Mapping[str, Any], env: Mapping[str, str] | None = None) -> SelfcheckConfig:
    env = os.environ if env is None else env
    data = source if isinstance(source, Mapping) else yaml.safe_load(Path(source).read_text(encoding="utf-8"))
    every = int(data.get("every_minutes") or 5)
    checks = []
    for item in data.get("checks") or []:
        kinds = [k for k in ("url", "watcher_status", "model") if item.get(k)]
        if len(kinds) != 1 or not item.get("name"):
            raise SettingsError(f"check {item}: needs a name and exactly one of url, watcher_status, model")
        target = "" if kinds[0] == "model" else str(item[kinds[0]])
        checks.append(Check(str(item["name"]), kinds[0], target, int(item.get("every_minutes") or every)))
    if not checks:
        raise SettingsError("selfcheck: no checks")
    alarm = data.get("alarm") or {}
    return SelfcheckConfig(
        checks=tuple(checks),
        state=Path(str(data.get("state") or "selfcheck.json")),
        every_minutes=every,
        alarm_url=value(alarm, "url", env, "alarm"),
        alarm_secret=value(alarm, "secret", env, "alarm"),
        repeat_minutes=int(alarm.get("repeat_minutes") or 60),
        tz=str(data.get("tz") or ""),
    )


def check_url(url: str, client: httpx.Client) -> tuple[bool, str]:
    try:
        response = client.get(url, timeout=10.0)
    except httpx.HTTPError as exc:
        return False, f"{type(exc).__name__}: {str(exc)[:120]}"
    try:
        body = response.json()
    except ValueError:
        body = {}
    if not 200 <= response.status_code < 300:
        return False, f"HTTP {response.status_code}"
    if isinstance(body, dict) and body.get("ok") is False:
        return False, "answers ok: false"
    return True, f"HTTP {response.status_code}"


def check_watcher(path: str, now: float) -> tuple[bool, str]:
    try:
        status = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, "the watcher has written no status yet"
    schedule = Schedule(**{k: v for k, v in (status.get("schedule") or {}).items() if k in Schedule.__annotations__})
    tick = float(status.get("tick_at") or 0)
    if in_window(schedule, now) and now - tick > 2.5 * schedule.every_minutes * 60:
        return False, f"盯守已经 {int((now - tick) // 60)} 分钟没有动静（应每 {schedule.every_minutes} 分钟一跳）"
    if status.get("outcome") == "error":
        return False, f"上一轮出错：{str(status.get('error') or '')[:200]}"
    if int(status.get("failed_deliveries") or 0):
        return False, f"上一轮有 {status['failed_deliveries']} 条信号没送到：{str(status.get('error') or '')[:200]}"
    return True, f"last tick {time.strftime('%H:%M', time.localtime(tick))}, {status.get('outcome')}"


def check_model(env: Mapping[str, str], client: httpx.Client) -> tuple[bool, str]:
    base = str(env.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com").rstrip("/")
    token = env.get("ANTHROPIC_AUTH_TOKEN") or env.get("ANTHROPIC_API_KEY") or ""
    model = env.get("AIRLOCK_MODEL") or env.get("ANTHROPIC_MODEL") or ""
    if not token or not model:
        return False, "no model settings (ANTHROPIC_AUTH_TOKEN, AIRLOCK_MODEL) to check with"
    headers = {"x-api-key": token, "Authorization": f"Bearer {token}", "anthropic-version": "2023-06-01"}
    body = {"model": model, "max_tokens": 1, "messages": [{"role": "user", "content": "ping"}]}
    try:
        response = client.post(f"{base}/v1/messages", json=body, headers=headers, timeout=30.0)
    except httpx.HTTPError as exc:
        return False, f"the model gateway does not answer: {type(exc).__name__}"
    if response.status_code != 200:
        return False, f"the model gateway answers HTTP {response.status_code}"
    return True, "the model answers"


class Selfcheck:
    def __init__(
        self,
        config: SelfcheckConfig,
        *,
        client: httpx.Client | None = None,
        alarm: Callable[[str], None] | None = None,
        env: Mapping[str, str] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config, self.clock = config, clock
        self.client = client or httpx.Client()
        self.env = os.environ if env is None else env
        self.alarm = alarm or self._webhook_alarm()
        try:
            self.state: dict[str, dict[str, Any]] = json.loads(config.state.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.state = {}

    def _webhook_alarm(self) -> Callable[[str], None]:
        if not self.config.alarm_url:
            return lambda text: logger.warning("ALARM (no alarm url configured): %s", text)
        hook = Webhook(self.config.alarm_url, self.config.alarm_secret)

        def send(text: str) -> None:
            card = {
                "header": {"title": {"tag": "plain_text", "content": text[:100]}, "template": "red"},
                "elements": [{"tag": "div", "text": {"tag": "plain_text", "content": text}}],
            }
            try:
                hook.send("", card)
            except LarkError as exc:
                logger.error("the alarm could not be sent (%s): %s", exc, text)

        return send

    def _run(self, check: Check, now: float) -> tuple[bool, str]:
        if check.kind == "url":
            return check_url(check.target, self.client)
        if check.kind == "watcher_status":
            return check_watcher(check.target, now)
        return check_model(self.env, self.client)

    def tick(self) -> list[dict[str, Any]]:
        now = self.clock()
        results = []
        for check in self.config.checks:
            row = self.state.setdefault(check.name, {})
            if now - float(row.get("last_run") or 0) < check.every_minutes * 60 - 5:
                continue
            ok, detail = self._run(check, now)
            row["last_run"], row["detail"] = now, detail
            if ok:
                if row.get("alarmed_at"):
                    self.alarm(f"✅ airlock 自检：{check.name} 恢复（{detail}）")
                row.update(fails=0, failing_since=None, alarmed_at=None)
            else:
                row["fails"] = int(row.get("fails") or 0) + 1
                row["failing_since"] = row.get("failing_since") or now
                due = not row.get("alarmed_at") or now - float(row["alarmed_at"]) >= self.config.repeat_minutes * 60
                if row["fails"] >= FAILS_BEFORE_ALARM and due:
                    since = time.strftime("%m-%d %H:%M", time.localtime(float(row["failing_since"])))
                    self.alarm(f"⚠️ airlock 自检：{check.name} 不正常：{detail}（自 {since} 起）")
                    row["alarmed_at"] = now
            results.append({"name": check.name, "ok": ok, "detail": detail})
        write_atomically(self.config.state, self.state)
        return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m airlock.extras.selfcheck", description=__doc__.splitlines()[0])
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        config = load_selfcheck(args.config)
    except (SettingsError, OSError) as exc:
        print(f"selfcheck: {exc}", file=sys.stderr)
        return 2
    if config.tz:
        os.environ["TZ"] = config.tz
        time.tzset()
    selfcheck = Selfcheck(config)
    if not args.once:
        # Started with everything else: give the rest a minute to listen before the first check,
        # or every start begins with a round of refused connections.
        time.sleep(START_AFTER_SECONDS)
    while True:
        for result in selfcheck.tick():
            logger.info("%s: %s — %s", result["name"], "ok" if result["ok"] else "FAILING", result["detail"])
        if args.once:
            return 0
        time.sleep(60)


if __name__ == "__main__":
    sys.exit(main())
