"""A report reaches whoever cannot open the console: the notification carries it, and the chat gets all of it.

The console usually runs on 127.0.0.1. A card's button to it works on that
computer and nowhere else, and the phone the card is read on is somewhere else.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from airlock.control.service import REPORT_CHARS
from airlock.extras.feishu import render
from tests.conftest import body_of, fenced, plan_doc
from tests.test_control_flow import Harness
from tests.test_feishu import PLAN, adapter, outlet

pytestmark = pytest.mark.anyio

KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


def payloads(h: Harness, event: str) -> list[dict[str, Any]]:
    return [body_of(r)["payload"] for r in h.hooks if body_of(r)["event"] == event]


@pytest.fixture
def h(config_dict: dict[str, Any], env: dict[str, str]) -> Harness:
    return Harness(config_dict, env)


async def test_a_notification_carries_the_whole_report_masked_and_bounded(h: Harness) -> None:
    work_id = await h.investigating()
    report = f"## Findings\n\nThe pool is exhausted. Token {KEY} was in the log.\n\n" + "detail " * 4000
    h.plane.receive_result("infra", {"work_id": work_id, "text": report})
    await h.plane.tick()
    answered = payloads(h, "work.answered")[-1]
    assert answered["lead"].startswith("The pool is exhausted.")
    assert KEY not in answered["report"] and "The pool is exhausted." in answered["report"]
    assert len(answered["report"]) == REPORT_CHARS and answered["report_truncated"] is True

    planned = await h.investigating("disk full")
    h.plane.receive_result("infra", {"work_id": planned, "text": fenced(plan_doc(), "Short: restart it.")})
    await h.plane.tick()
    ready = payloads(h, "plan.ready")[-1]
    assert ready["report"] == "Short: restart it." and ready["report_truncated"] is False
    assert ready["steps"] == [
        {"worker": "ops", "target": "demo/api", "what": "echo restarting api"},
        {"worker": "ops", "target": "demo/api", "what": "true"},
    ]


def test_the_whole_report_follows_its_card_into_the_thread(tmp_path: Path) -> None:
    _, cards, fake, client = adapter(tmp_path)
    paragraph = "证据：连接池 10/10，等待 5000ms。" * 60  # ~1300 characters
    report = f"## 结论\n\n{paragraph}\n\n{paragraph}\n\n## 建议\n\n<at id=all></at> 不要重启 [现在]\n\n{paragraph}"
    payload = {
        "work_id": "w1",
        "title": "Checkout is slow",
        "link": "http://127.0.0.1:18080/work/w1",
        "lead": "连接池满了。",
        "report": report,
        "report_truncated": False,
    }
    answer = outlet(client, 1, "work.answered", payload).json()
    assert answer["status"] == "sent" and answer["report_cards"] == 3
    assert [s["kind"] for s in fake.sent] == ["send", "reply", "reply", "reply"]
    assert all(s["path"].endswith("/om_1/reply") and s["reply_in_thread"] for s in fake.sent[1:])
    first = json.dumps(json.loads(fake.sent[0]["content"]), ensure_ascii=False)
    assert render.IN_THREAD in first and '"content": "看报告（电脑上）"' in first
    parts = [json.loads(s["content"]) for s in fake.sent[1:]]
    assert [p["header"]["title"]["content"] for p in parts] == [f"报告全文 {i}/3：Checkout is slow" for i in (1, 2, 3)]
    pieces = [e["text"]["content"] for p in parts for e in p["elements"] if e.get("tag") == "div"]
    assert all(len(piece) <= render.CHUNK_CHARS + 10 for piece in pieces)  # cut between paragraphs, escapes aside
    text = "\n\n".join(pieces)
    assert text.startswith("**结论**") and "**建议**" in text and text.count(paragraph) == 3
    assert "\\<at id=all>\\</at> 不要重启 \\[现在\\]" in text  # neutralised like every other field: no one is paged
    assert cards.card("om_3")["work_id"] == "w1"  # a reply under a piece of the report is a reply on the item
    assert outlet(client, 1, "work.answered", payload).json()["status"] == "already sent"
    assert len(fake.sent) == 4


def test_a_short_report_stays_on_its_card_and_a_long_one_says_where_it_stops() -> None:
    short = {
        "title": "t",
        "link": "https://console.example/work/w1",
        "lead": "Nothing to change.",
        "report": "Nothing to change.",
    }
    assert render.report_cards("work.answered", short) == []
    assert render.report_cards("work.answered", {**short, "report": "## Findings\n\nNothing to change."}) == []
    card = json.dumps(render.for_event("work.answered", short), ensure_ascii=False)
    assert render.IN_THREAD not in card and '"content": "看报告"' in card  # a console you can reach: no warning
    assert render.report_cards("run.finished", {**short, "report": "x" * 10}) == []

    long = {**short, "report": "\n\n".join(["段落" * 1000] * 20), "report_truncated": False}
    pieces = render.report_cards("work.answered", long)
    assert len(pieces) == render.MAX_CHUNKS
    assert "后面没有发" in json.dumps(pieces[-1], ensure_ascii=False)
    assert "后面没有发" not in json.dumps(pieces[0], ensure_ascii=False)
    cut = render.report_cards("work.answered", {**short, "report": "a\n\nb", "report_truncated": True})
    assert len(cut) == 1 and "后面没有发" in json.dumps(cut[0], ensure_ascii=False)


def test_a_plan_card_lists_its_steps(tmp_path: Path) -> None:
    steps = [{"worker": "ops", "target": "demo/api", "what": f"echo step {i}"} for i in range(12)]
    card = json.dumps(render.for_event("plan.ready", {**PLAN, "steps": steps}), ensure_ascii=False)
    assert "**步骤**\\n1. ops · demo/api：echo step 0" in card and "10. ops · demo/api：echo step 9" in card
    assert "echo step 10" not in card and "……还有 2 步" in card
