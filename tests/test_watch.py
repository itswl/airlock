"""The watcher: a deterministic scan, a judge that holds nothing, and deliveries this process signs."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from airlock.crypto import verify
from airlock.extras.watch.__main__ import run_round, seconds_to_next
from airlock.extras.watch.chat import is_fragment, pick_ref
from airlock.extras.watch.config import WatchConfigError, load_watch
from airlock.extras.watch.deliver import deliver
from airlock.extras.watch.jira import scan_jira
from airlock.extras.watch.judge import Signal, default_engine, parse
from airlock.extras.watch.mcp import McpClient, McpError
from airlock.extras.watch.scan import Scanner, in_window, trim
from airlock.runner.engine import StubEngine, StubTurn
from airlock.runner.recorder import Recorder, read_lines, verify_lines

NOW = 1_790_000_000.0  # the fake clock; every message below is placed relative to it
PREFIX = "chat."


def iso(at: float) -> str:
    return datetime.fromtimestamp(at, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeChat:
    """Just enough of a chat platform's MCP server, answering as an event stream the way a real one did."""

    def __init__(self) -> None:
        self.feeds: dict[str, dict[str, Any]] = {}
        self.messages: dict[str, list[dict[str, Any]]] = {}
        self.broken: dict[str, str] = {}
        self.ambiguous: dict[str, list[dict[str, Any]]] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def say(self, feed: str, who: str, text: str, at: float, *, group: bool = True, kind: str = "") -> None:
        self.messages.setdefault(feed, []).append(
            {"send_at": iso(at), "send_name": who, "content": text, "message_type": kind}
        )
        row = self.feeds.setdefault(feed, {"name": feed, "chat_type_label": "group chat" if group else "single chat"})
        row["last_message_send_at"] = iso(
            max(at, datetime.fromisoformat(row.get("last_message_send_at", iso(0)).replace("Z", "+00:00")).timestamp())
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        message = json.loads(request.content)
        if message["method"] == "initialize":
            return self._reply(message["id"], {"protocolVersion": "2025-06-18", "capabilities": {}})
        name, args = message["params"]["name"], message["params"]["arguments"]
        assert name.startswith(PREFIX), name
        tool = name[len(PREFIX) :]
        self.calls.append((tool, args))
        if tool == "list_folder_feeds":
            return self._tool(message["id"], {"feeds": list(self.feeds.values())})
        if tool == "search_contact":
            return self._tool(message["id"], {"candidates": self.ambiguous.get(args["name"], [])})
        if tool == "search_chat_records":
            feed = args.get("contact_name") or next(
                (n for n, c in self.ambiguous.items() for x in c if x.get("opaque_ref") == args.get("opaque_ref")), ""
            )
            if args.get("contact_name") in self.ambiguous:
                return self._tool(message["id"], None, error="Multiple matches for that name; retry with target.ref")
            if feed in self.broken:
                return self._tool(message["id"], None, error=self.broken[feed])
            lo, hi = int(args["from_time"]), int(args["to_time"])
            got = [
                m
                for m in self.messages.get(feed, [])
                if lo <= datetime.fromisoformat(m["send_at"].replace("Z", "+00:00")).timestamp() <= hi
            ]
            return self._tool(message["id"], {"messages": list(reversed(got))[: int(args.get("limit") or 60)]})
        return self._tool(message["id"], None, error=f"MCP error -32602: Tool {name} not found")

    def _tool(self, request_id: int, structured: Any, error: str = "") -> httpx.Response:
        if error:
            return self._reply(request_id, {"content": [{"type": "text", "text": error}], "isError": True})
        return self._reply(
            request_id, {"content": [{"type": "text", "text": "Found."}], "structuredContent": structured}
        )

    def _reply(self, request_id: int, result: dict[str, Any]) -> httpx.Response:
        body = f"event: message\ndata: {json.dumps({'jsonrpc': '2.0', 'id': request_id, 'result': result})}\n\n"
        return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> float:
        return self.now


def config_for(tmp_path: Path, **overrides: Any) -> Any:
    brief = tmp_path / "brief.md"
    brief.write_text("只报需要我亲自处理的事。\n")
    data: dict[str, Any] = {
        "name": "watch",
        "state_dir": str(tmp_path / "state"),
        "brief_file": str(brief),
        "schedule": {"every_minutes": 20, "window": "09:30-19:30", "days": "1-5"},
        "chat": {
            "url": "http://chat.invalid/mcp/",
            "tool_prefix_env": "T_PREFIX",
            "me_env": "T_ME",
            "bots": ["Alert Bot"],
            "batch_feeds_env": "T_BATCH",
            "batch_minutes": 60,
        },
        "tasks": {"url": "http://airlock.invalid/v1/intake/watch", "secret_env": "T_TASKS"},
        "notes": {"url": "http://adapter.invalid/notice", "secret_env": "T_NOTES"},
        "judge": {"mcp_allowed": ["mcp__chat__*"]},
        **overrides,
    }
    env = {"T_PREFIX": PREFIX, "T_ME": "Me", "T_BATCH": "noisy", "T_TASKS": "t" * 32, "T_NOTES": "n" * 32}
    return load_watch(data, env)


def scanner(tmp_path: Path, chat: FakeChat, clock: Clock, **overrides: Any) -> Scanner:
    config = config_for(tmp_path, **overrides)
    client = McpClient(config.chat.url, prefix=config.chat.tool_prefix, transport=httpx.MockTransport(chat.handler))
    return Scanner(config, chat=client, clock=clock)


def test_the_first_round_lays_a_floor_and_later_rounds_hand_over_only_what_is_new(tmp_path: Path) -> None:
    chat, clock = FakeChat(), Clock()
    chat.say("ops", "Ann", "old news from last week", NOW - 7 * 86400)
    scan = scanner(tmp_path, chat, clock)
    assert scan.run(force=True) is None  # the floor: nothing old is reported
    clock.now += 1200
    chat.say("ops", "Ann", "can you look at the deploy failure on staging?", NOW + 600)
    chat.say("ops", "Me", "my own message is not a signal", NOW + 610)
    chat.say("ops", "Alert Bot [bot]", "CPU 91%", NOW + 620)
    chat.say("ops", "Bob", "👍", NOW + 630)
    chat.say("ops", "Bob", "also the cert expires friday", NOW + 640)
    found = scan.run(force=True)
    assert found is not None and set(found.offered) == {"ops"}
    assert "### ops" in found.digest and "deploy failure" in found.digest and "cert expires" in found.digest
    for noise in ("my own message", "CPU 91%", "👍", "old news"):
        assert noise not in found.digest
    assert found.digest.index("cert expires") < found.digest.index("deploy failure")  # newest first
    scan.commit(found)
    clock.now += 1200
    assert scan.run(force=True) is None  # read once, never twice


def test_a_round_that_was_not_committed_is_read_again(tmp_path: Path) -> None:
    chat, clock = FakeChat(), Clock()
    chat.say("ops", "Ann", "hello", NOW - 60)
    scan = scanner(tmp_path, chat, clock)
    scan.run(force=True)
    clock.now += 1200
    chat.say("ops", "Ann", "please restart the worker", NOW + 300)
    assert scan.run(force=True) is not None
    clock.now += 1200
    again = scan.run(force=True)  # the judge failed, so nothing was committed
    assert again is not None and "restart the worker" in again.digest


def test_a_noisy_conversation_waits_for_its_batch_and_loses_nothing(tmp_path: Path) -> None:
    chat, clock = FakeChat(), Clock()
    chat.say("noisy", "Ann", "hi", NOW - 60)
    scan = scanner(tmp_path, chat, clock)
    scan.run(force=True)
    clock.now += 1200
    chat.say("noisy", "Ann", "first thing worth reading", NOW + 100)
    assert scan.run(force=True) is None  # held
    clock.now += 1800
    chat.say("noisy", "Bob", "second thing worth reading", NOW + 1500)
    assert scan.run(force=True) is None  # still held: 30 minutes since the batch began
    clock.now += 1800
    due = scan.run(force=True)  # an hour since the first new message was seen
    assert due is not None and "first thing" in due.digest and "second thing" in due.digest


def test_an_unreachable_conversation_is_said_once_then_every_six_hours(tmp_path: Path) -> None:
    chat, clock = FakeChat(), Clock()
    chat.say("vendor", "Ann", "hi", NOW - 60)
    scan = scanner(tmp_path, chat, clock)
    scan.run(force=True)
    chat.broken["vendor"] = "permission denied"
    said = []
    for step in range(20):
        clock.now += 1200
        chat.say("vendor", "Ann", f"message {step}", clock.now - 30)
        found = scan.run(force=True)
        if found is not None:
            said.append(step)
            assert "vendor" in found.offered and "vendor 取不到" in found.digest
            scan.commit(found)
    assert said == [0, 18]  # the first round, and six hours later
    del chat.broken["vendor"]
    clock.now += 1200
    back = scan.run(force=True)
    assert back is not None and "message 19" in back.digest and "取不到" not in back.digest


def test_two_conversations_with_one_name_are_told_apart_by_reference(tmp_path: Path) -> None:
    chat, clock = FakeChat(), Clock()
    chat.say("Ann", "Ann", "hi", NOW - 60, group=False)
    scan = scanner(tmp_path, chat, clock)
    scan.run(force=True)
    clock.now += 1200
    chat.say("Ann", "Ann", "are you free at 3?", NOW + 300, group=False)
    chat.ambiguous["Ann"] = [
        {"ret_type": "contact", "name": "Ann", "opaque_ref": "c-1"},
        {"ret_type": "feed", "name": "Ann", "opaque_ref": "f-1"},
    ]
    chat.messages["f-1"] = chat.messages["Ann"]
    found = scan.run(force=True)
    assert found is not None and "are you free" in found.digest
    assert pick_ref(chat.ambiguous["Ann"] + [{"ret_type": "feed", "name": "Ann", "opaque_ref": "f-2"}], "Ann") == ""


def test_the_digest_keeps_the_newest_messages_across_conversations() -> None:
    from airlock.extras.watch.chat import Message

    found = [("a", [Message(3, "x", "a3" * 20), Message(1, "x", "a1" * 20)]), ("b", [Message(2, "y", "b2" * 20)])]
    kept, dropped = trim(found, 140)
    assert dropped == 1 and [(n, [m.body[:2] for m in ms]) for n, ms in kept] == [("a", ["a3"]), ("b", ["b2"])]
    assert is_fragment("、😂") and is_fragment("也") and not is_fragment("不急，等我看看")


def test_the_working_hours_are_read_in_the_configured_zone(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = config_for(tmp_path)
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()
    try:
        monday_10 = datetime(2026, 9, 21, 10, 0, tzinfo=UTC).timestamp()
        assert in_window(config.schedule, monday_10)
        assert not in_window(config.schedule, monday_10 - 3600)  # 09:00
        assert not in_window(config.schedule, monday_10 - 2 * 86400)  # Saturday
        assert seconds_to_next(20, datetime(2026, 9, 21, 10, 7, 30, tzinfo=UTC).timestamp()) == pytest.approx(750)
    finally:
        monkeypatch.undo()
        time.tzset()


def test_a_tool_that_answers_with_an_error_inside_its_result_is_unreachable_not_quiet() -> None:
    chat = FakeChat()
    client = McpClient("http://chat.invalid/", prefix=PREFIX, transport=httpx.MockTransport(chat.handler))
    with pytest.raises(McpError, match="not found"):
        client.call("no_such_tool")


def jira_fetch(pages: dict[str, Any]) -> Any:
    def fetch(path: str, params: dict[str, str]) -> dict[str, Any]:
        return pages[path]

    return fetch


def test_jira_changes_are_reported_once_and_your_own_are_not(tmp_path: Path) -> None:
    source = config_for(tmp_path, jira={"site": "https://t.invalid", "email": "e", "token": "t", "project": "OPS"}).jira
    stamp = "2026-09-21T10:00:00.000+0000"
    pages = {
        "/rest/api/3/myself": {"accountId": "me"},
        "/rest/api/3/search/jql": {"issues": [{"key": "OPS-7"}]},
        "/rest/api/3/issue/OPS-7": {
            "fields": {
                "summary": "Rotate the TLS cert",
                "status": {"name": "In Progress"},
                "created": "2026-09-01T10:00:00.000+0000",
                "reporter": {"accountId": "ann", "displayName": "Ann"},
                "assignee": {"displayName": "Me"},
                "comment": {
                    "comments": [
                        {
                            "created": stamp,
                            "author": {"accountId": "ann", "displayName": "Ann"},
                            "body": {
                                "type": "doc",
                                "content": [
                                    {"type": "paragraph", "content": [{"type": "text", "text": "done on staging"}]}
                                ],
                            },
                        },
                        {"created": stamp, "author": {"accountId": "me", "displayName": "Me"}, "body": {}},
                    ]
                },
            },
            "changelog": {
                "histories": [
                    {
                        "created": stamp,
                        "author": {"accountId": "ann", "displayName": "Ann"},
                        "items": [{"field": "status", "fromString": "To Do", "toString": "In Progress"}],
                    }
                ]
            },
        },
    }
    state: dict[str, Any] = {}
    at = datetime(2026, 9, 21, 10, 5, tzinfo=UTC).timestamp()
    lines = scan_jira(source, state, jira_fetch(pages), at)
    assert lines[0] == "OPS-7 [In Progress] Rotate the TLS cert"
    assert any("To Do → In Progress" in line for line in lines) and any("done on staging" in line for line in lines)
    assert sum("💬" in line for line in lines) == 1  # not my own comment
    assert scan_jira(source, state, jira_fetch(pages), at + 1200) == []  # the same changes, never twice


def test_the_judge_s_signals_must_name_what_the_round_offered() -> None:
    offered = {"ops": 1.0, "OPS-7": 1.0}
    text = """Two things.

```signals
[
  {"title": "Ann asks you to look at the staging deploy", "detail": "in ops", "level": "high", "kind": "task", "conversation": "ops"},
  {"title": "made up", "detail": "", "level": "high", "kind": "task", "conversation": "somewhere else"},
  {"title": "Cert ticket moved", "detail": "", "level": "low", "kind": "note", "origin": "Jira / OPS-7"},
  {"title": "Jira key not offered", "level": "low", "kind": "note", "origin": "Jira / OPS-9"},
  {"title": "vendor unreachable", "level": "high", "kind": "task", "origin": "scan / vendor"}
]
```"""
    signals, dropped = parse(text, offered, "chat")
    assert [(s.title[:9], s.origin, s.level, s.kind) for s in signals] == [
        ("Ann asks ", "chat / ops", "high", "task"),
        ("Cert tick", "Jira / OPS-7", "low", "note"),
        ("vendor un", "scan / vendor", "low", "note"),  # a relayed ⚠️ never buys an investigation
    ]
    assert len(dropped) == 2 and "did not offer" in dropped[0]
    assert parse("no block here", offered, "chat")[1] == ["the answer has no ```signals block"]


def test_tasks_go_to_airlock_and_notes_to_the_notice_door_signed_by_this_process(tmp_path: Path) -> None:
    config = config_for(tmp_path)
    seen: list[tuple[str, dict[str, Any]]] = []

    def door(request: httpx.Request) -> httpx.Response:
        secret = "t" * 32 if "intake" in str(request.url) else "n" * 32
        verify(secret, request.content, request.headers)
        seen.append((request.url.host, json.loads(request.content)))
        return httpx.Response(202 if "intake" in str(request.url) else 200)

    signals = [
        Signal("look at staging", "ctx", "high", "task", "chat / ops", "ops"),
        Signal("cert moved", "", "low", "note", "Jira / OPS-7", "OPS-7"),
    ]
    done = deliver(config, signals, NOW, client=httpx.Client(transport=httpx.MockTransport(door)))
    # The task goes to airlock, then is carded in the notices chat too; the note only to the notices chat.
    assert [(d.door, d.ok) for d in done] == [("tasks", True), ("notes", True), ("notes", True)]
    assert [host for host, _ in seen] == ["airlock.invalid", "adapter.invalid", "adapter.invalid"]
    assert seen[0][1]["key"] == deliver.__globals__["body_of"](signals[0], "watch", NOW)["key"]


def test_a_round_end_to_end_with_a_stub_judge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    chat, clock = FakeChat(), Clock()
    chat.say("ops", "Ann", "hi", NOW - 60)
    scan = scanner(tmp_path, chat, clock)
    config = scan.config
    record = Recorder(config.state_dir / "rounds.jsonl")
    posted: list[dict[str, Any]] = []
    real_client = httpx.Client

    def door(request: httpx.Request) -> httpx.Response:
        posted.append(json.loads(request.content))
        return httpx.Response(202)

    monkeypatch.setattr(
        "airlock.extras.watch.deliver.httpx.Client", lambda **kw: real_client(transport=httpx.MockTransport(door))
    )
    monkeypatch.setattr("airlock.extras.watch.__main__.time.time", clock)
    assert run_round(config, scan, record, force=True)["outcome"] == "quiet"
    clock.now += 1200
    chat.say("ops", "Ann", "can you rotate the staging cert today?", NOW + 300)
    answer = '```signals\n[{"title": "Rotate the staging cert", "detail": "Ann in ops", "level": "high", "kind": "task", "conversation": "ops"}]\n```'
    stub = StubEngine(lambda request: StubTurn(text=answer))
    dry = run_round(config, scan, record, force=True, dry_run=True, engine_factory=lambda: stub)
    assert dry["outcome"] == "dry-run" and dry["signals"][0]["title"] == "Rotate the staging cert" and posted == []
    result = run_round(config, scan, record, force=True, engine_factory=lambda: stub)
    assert result["outcome"] == "fired" and [p["title"] for p in posted] == ["Rotate the staging cert"] * 2
    status = json.loads((config.state_dir / "status.json").read_text())
    assert status["outcome"] == "fired" and status["signals"] == 1 and status["failed_deliveries"] == 0
    lines = read_lines(config.state_dir / "rounds.jsonl")
    assert [line["kind"] for line in lines][-1] == "round" and verify_lines(lines)["intact"]
    case = Path(lines[-1]["data"]["case"]).read_text()
    assert "rotate the staging cert" in case and "```signals" in case


def test_the_judge_is_given_no_built_in_tools(tmp_path: Path) -> None:
    engine = default_engine(config_for(tmp_path))()
    assert engine.tools == ()


def test_names_that_are_yours_come_from_the_environment(tmp_path: Path) -> None:
    config = config_for(tmp_path)
    assert config.chat.tool_prefix == PREFIX and config.chat.me == "Me" and config.chat.batch_feeds == ("noisy",)
    with pytest.raises(WatchConfigError, match="T_MISSING, which is unset"):
        config_for(tmp_path, tasks={"url": "http://x.invalid/", "secret_env": "T_MISSING"})
    with pytest.raises(WatchConfigError, match="nothing to watch"):
        config_for(tmp_path, chat=None)


WATCH_SOURCE = {
    "name": "watch",
    "verify": "hmac",
    "secret_env": "T_WATCH",
    "accept": [{}],
    "map": {"title": "{title}", "body": "{detail}\n\n来源：{origin}", "key": "{key}"},
    "labels": ["watch"],
}


def test_airlock_takes_the_watcher_s_task_as_a_work_item_and_a_repeat_joins_it(
    tmp_path: Path, config_dict: dict[str, Any], env: dict[str, str]
) -> None:
    from airlock.config import load_control
    from airlock.control.service import ControlPlane

    plane = ControlPlane(
        load_control({**config_dict, "sources": [*config_dict["sources"], WATCH_SOURCE]}, {**env, "T_WATCH": "t" * 32})
    )

    def intake(request: httpx.Request) -> httpx.Response:
        outcome = plane.intake("watch", request.headers, request.content)
        return httpx.Response(outcome.status, json=outcome.body)

    config = config_for(tmp_path)
    task = Signal("Rotate the staging cert", "Ann asked in ops", "high", "task", "chat / ops", "ops")
    client = httpx.Client(transport=httpx.MockTransport(intake))
    config = config_for(tmp_path, notes=None)
    first = deliver(config, [task], NOW, client=client)
    again = deliver(config, [task], NOW + 60, client=client)
    assert [(d.door, d.ok) for d in first + again] == [("tasks", True), ("tasks", True)]
    items = plane.db.all("SELECT * FROM work_items")
    assert len(items) == 1 and items[0]["title"] == "Rotate the staging cert"
    assert "Ann asked in ops" in items[0]["body"] and "chat / ops" in items[0]["body"]
    assert json.loads(items[0]["labels"]) == ["watch"]
