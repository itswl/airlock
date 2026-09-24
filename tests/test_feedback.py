"""The feedback loop: what you said (ratings), what you did (outcomes), and what an investigator may remember."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from airlock.config import load_control
from airlock.control.app import create_app
from airlock.control.memory import lift
from airlock.control.service import ControlPlane
from airlock.runner.investigator import load_node, system_prompt
from tests.conftest import fenced, plan_doc
from tests.test_control_flow import Harness
from tests.test_web import csrf_of, login

pytestmark = pytest.mark.anyio

REPORT = "Two config lines and a restart.\n\nDetails.\n\nMEMORY-SUGGESTION: the staging database is restored every Sunday at 03:00\nMEMORY-SUGGESTION: api-7 runs the old pool\n"


@pytest.fixture
def h(config_dict: dict[str, Any], env: dict[str, str]) -> Harness:
    return Harness(config_dict, env)


async def test_a_rating_is_kept_once_per_item_and_every_one_is_in_the_ledger(h: Harness) -> None:
    work_id = await h.investigating()
    h.plane.receive_result("infra", {"work_id": work_id, "text": "Nothing to change."})
    assert h.plane.rate(work_id, "great").status == 400
    assert h.plane.rate("nope", "useful").status == 404
    assert h.plane.rate(work_id, "useful", "found it in two minutes").ok
    assert h.plane.rate(work_id, "useless", "wrong service").ok
    assert h.plane.rating(work_id)["rating"] == "useless"
    assert h.kinds(work_id).count("work.rated") == 2
    assert h.state(work_id) == "answered"  # a rating decides nothing


async def test_an_adapter_rates_only_for_a_mapped_person(config_dict: dict[str, Any], env: dict[str, str]) -> None:
    config = {**config_dict, "adapters": [{"name": "lark", "secret_env": "T_ADAPTER", "identities": ["ou_me"]}]}
    h = Harness(config, {**env, "T_ADAPTER": "a" * 32})
    work_id = await h.investigating()
    assert (
        h.plane.adapter_rating("lark", {"work_id": work_id, "rating": "useful", "platform_user": "ou_x"}).status == 403
    )
    assert h.plane.adapter_rating("lark", {"work_id": work_id, "rating": "useful", "platform_user": "ou_me"}).ok
    assert h.plane.rating(work_id)["via"] == "adapter:lark"


async def test_suggestions_are_lifted_out_queued_and_only_an_accept_writes_memory(h: Harness) -> None:
    kept, found = lift(REPORT)
    assert "MEMORY-SUGGESTION" not in kept and found[0].startswith("the staging database")
    work_id = await h.investigating()
    h.plane.receive_result("infra", {"work_id": work_id, "text": REPORT})
    texts = [m["text"] for m in h.plane.db.all("SELECT text FROM messages WHERE work_id = ?", [work_id])]
    assert not any("MEMORY-SUGGESTION" in t for t in texts)
    pending = h.plane.suggestions()
    assert [s["text"] for s in pending] == [
        "api-7 runs the old pool",
        "the staging database is restored every Sunday at 03:00",
    ]
    memory_file = h.plane.memory_file("infra")
    assert not memory_file.exists()  # nothing is remembered until you say so
    first, second = pending[1]["id"], pending[0]["id"]
    assert h.plane.decide_suggestion(first, accept=True).ok
    assert h.plane.decide_suggestion(second, accept=False).ok
    assert h.plane.decide_suggestion(first, accept=True).status == 404
    text = memory_file.read_text(encoding="utf-8")
    assert "the staging database is restored every Sunday at 03:00" in text and "api-7" not in text
    kinds = h.kinds(work_id)
    assert kinds.count("memory.suggested") == 2 and "memory.accepted" in kinds and "memory.dismissed" in kinds
    # The same fact proposed again while one is pending is queued once.
    h.plane._suggest("infra", work_id, ["a new fact"])
    h.plane._suggest("infra", work_id, ["a new fact"])
    assert [s["text"] for s in h.plane.suggestions()].count("a new fact") == 1
    # And a report on an item the investigator no longer holds is refused, suggestions and all.
    assert (
        h.plane.receive_result("infra", {"work_id": work_id, "text": "MEMORY-SUGGESTION: sneaked in\n"}).status >= 400
    )
    assert "sneaked in" not in [s["text"] for s in h.plane.suggestions()]


def test_the_investigator_reads_what_was_accepted_every_run(tmp_path: Path) -> None:
    memory = tmp_path / "infra.md"
    env = {"AIRLOCK_PROFILE": "infra", "AIRLOCK_SECRET": "s" * 32, "AIRLOCK_CONTROL_URL": "http://control",
           "AIRLOCK_WORKDIR": str(tmp_path), "AIRLOCK_MEMORY_FILE": str(memory)}  # fmt: skip
    config = load_node(env)
    assert "## Remembered" not in system_prompt(config)
    memory.write_text("# 记住的事实\n\n- the staging database is restored every Sunday\n")
    prompt = system_prompt(config)
    assert "## Remembered" in prompt and "restored every Sunday" in prompt


async def test_the_report_counts_what_you_did_as_well_as_what_you_said(h: Harness) -> None:
    done, current, approval = await h.running()
    h.clock.now += 30
    h.plane.receive_run_result(
        {"approval_id": approval, "plan_hash": current["plan_hash"], "status": "done", "groups": []}
    )
    rejected, _ = await h.ready()
    h.plane.reject(rejected, via="web", reason="not now")
    asked = await h.investigating()
    h.plane.receive_result(
        "infra", {"work_id": asked, "text": "Nothing to change.", "cost_usd": 0.02, "usage": {"input_tokens": 100}}
    )
    h.plane.operator_message(asked, "why not the other pool?", via="web")
    quiet = await h.investigating()
    h.plane.receive_result("infra", {"work_id": quiet, "text": "Nothing to change.", "cost_usd": 0.01})
    h.plane.rate(quiet, "useless")
    invalid = await h.investigating()
    bad = plan_doc(steps=[{"worker": "ops", "target": "demo/api", "argv": ["rm", "-rf", "/"]}])
    h.plane.receive_result("infra", {"work_id": invalid, "text": fenced(bad), "cost_usd": 0.05})
    report = h.plane.report(7)
    by_id = {r["id"]: r for r in report["items"]}
    assert by_id[done]["outcome"] == "acted_on"
    assert by_id[rejected]["outcome"] == "rejected"
    assert by_id[quiet]["outcome"] == "no_response" and by_id[quiet]["rating"] == "useless"
    assert by_id[invalid]["first_plan_valid"] is False
    assert report["ratings"] == {"useful": 0, "useless": 1, "unrated": report["work_items"] - 1}
    assert report["runs"] == {"done": 1}
    assert report["investigations"]["cost_usd"] == pytest.approx(0.08)  # an invalid plan's round is paid for too
    assert report["plans"]["items_with_plan"] >= 2 and report["approvals"]["count"] == 1
    # Asked about, then re-opened: still investigating until it answers again.
    assert by_id[asked]["outcome"] in ("in_progress", "discussed")


def test_the_console_shows_the_report_the_memory_and_the_rating_box(
    config_dict: dict[str, Any], env: dict[str, str]
) -> None:
    plane = ControlPlane(load_control(config_dict, env))
    client = TestClient(create_app(plane.config, plane=plane, run_loop=False), follow_redirects=False)
    login(client)
    work_id = str(plane.manual_signal("API 5xx", "error rate 7%").body["work_id"])
    plane.db.execute("UPDATE work_items SET state = 'answered' WHERE id = ?", [work_id])
    page = client.get(f"/work/{work_id}").text
    assert "这次调查帮上忙了吗" in page
    answer = client.post(f"/work/{work_id}/rate", data={"rating": "useful", "note": "快", "csrf": csrf_of(page)})
    assert answer.status_code == 303 and plane.rating(work_id)["rating"] == "useful"
    report = client.get("/report?days=30")
    assert report.status_code == 200 and "API 5xx" in report.text and "有用" in report.text
    assert client.get("/report.json").json()["ratings"]["useful"] == 1
    plane._suggest("infra", work_id, ["a fact worth keeping"])
    memory_page = client.get("/memory").text
    assert "a fact worth keeping" in memory_page
    suggestion = plane.suggestions()[0]["id"]
    assert client.post(f"/memory/{suggestion}/accept", data={"csrf": csrf_of(memory_page)}).status_code == 303
    assert "a fact worth keeping" in plane.memory_file("infra").read_text(encoding="utf-8")
    outsider = TestClient(create_app(plane.config, plane=plane, run_loop=False), follow_redirects=False)
    assert outsider.get("/report").status_code == 303 and outsider.get("/memory").status_code == 303


def test_a_bare_useful_under_a_card_is_a_rating_and_anything_more_is_a_message(tmp_path: Path) -> None:
    from airlock.crypto import verify
    from airlock.extras.feishu.inbound import handle
    from tests.test_feishu import ADAPTER, PLAN, adapter, message_event, outlet

    config, cards, _, client = adapter(tmp_path)
    outlet(client, 1, "plan.ready", PLAN)
    posted: list[tuple[str, dict[str, Any]]] = []

    def control(request: httpx.Request) -> httpx.Response:
        verify(ADAPTER, request.content, request.headers)
        posted.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={})

    http = httpx.Client(transport=httpx.MockTransport(control))
    assert handle(config, cards, message_event(root="om_1", text="@_user_1 有用"), client=http).startswith(
        "rating on w1"
    )
    handle(config, cards, message_event(root="om_1", text="@_user_1 没用，再查查", message_id="m2"), client=http)
    assert posted[0] == ("/v1/adapters/feishu/rating", {"work_id": "w1", "rating": "useful", "platform_user": "ou_me"})
    assert posted[1][0] == "/v1/adapters/feishu/message" and posted[1][1]["text"] == "没用，再查查"


def test_the_watcher_s_report_counts_rounds_that_cost_nothing(tmp_path: Path) -> None:
    from airlock.extras.watch.__main__ import report
    from airlock.runner.recorder import Recorder

    record = Recorder(tmp_path / "rounds.jsonl")
    for _ in range(3):
        record.write("round.quiet")
    record.write(
        "round",
        outcome="fired",
        digest_bytes=2000,
        judge={"signals": 2, "dropped": ["x"], "cost_usd": 0.2},
        deliveries=[
            {"door": "tasks", "kind": "task", "level": "high", "ok": True},
            {"door": "notes", "kind": "task", "level": "high", "ok": True},
            {"door": "notes", "kind": "note", "level": "low", "ok": False},
        ],
    )
    got = report(tmp_path / "rounds.jsonl", 7)
    assert got["quiet_rounds"] == 3 and got["judged_rounds"] == 1
    assert (got["tasks"], got["notes"], got["high"]) == (1, 1, 1)
    assert got["dropped_signals"] == 1 and got["failed_deliveries"] == 1 and got["cost_usd"] == 0.2
