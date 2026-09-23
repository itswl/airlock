"""The control plane's state machine, with the investigators and the launcher faked at the HTTP edge."""

from __future__ import annotations

import copy
from typing import Any

import httpx
import pytest

from airlock.config import load_control
from airlock.control.outbox import MAX_ATTEMPTS
from airlock.control.service import DISPATCH_BACKOFF_SECONDS, ControlPlane
from airlock.crypto import verify
from airlock.plans import parse_plan, plan_hash
from tests.conftest import Router, body_of, fenced, plan_doc

pytestmark = pytest.mark.anyio


class Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


class Harness:
    def __init__(self, config_dict: dict[str, Any], env: dict[str, str]) -> None:
        self.env = env
        self.router = Router()
        self.clock = Clock()
        self.config = load_control(config_dict, env)
        self.plane = ControlPlane(self.config, client=httpx.AsyncClient(transport=self.router), clock=self.clock)
        self.investigations: list[dict[str, Any]] = []
        self.launches: list[dict[str, Any]] = []
        self.hooks: list[httpx.Request] = []
        self.launch_answer: tuple[int, dict[str, Any]] = (202, {"status": "accepted"})
        self.consult_answer = "code says: the deploy at 09:10 changed the pool size"
        self.router.handle("infra", self._investigator("T_INFRA"))
        self.router.handle("code", self._investigator("T_CODE"))
        self.router.handle("launcher", self._launcher)
        self.router.handle("hooks", self._hook)

    def _investigator(self, secret_name: str):  # noqa: ANN202
        def handler(request: httpx.Request) -> httpx.Response:
            verify(self.env[secret_name], request.content, request.headers, now=self.clock())
            if request.url.path == "/consult":
                return httpx.Response(200, json={"answer": self.consult_answer})
            self.investigations.append({"to": request.url.host, **body_of(request)})
            return httpx.Response(202, json={"status": "accepted"})

        return handler

    def _launcher(self, request: httpx.Request) -> httpx.Response:
        verify(self.env["T_LAUNCHER"], request.content, request.headers, now=self.clock())
        self.launches.append({"path": request.url.path, **body_of(request)})
        if request.url.path == "/cancel":
            return httpx.Response(200, json={"status": "cancelling"})
        status, body = self.launch_answer
        return httpx.Response(status, json=body)

    def _hook(self, request: httpx.Request) -> httpx.Response:
        self.hooks.append(request)
        return httpx.Response(200)

    def new_work(self, title: str = "API 5xx") -> str:
        outcome = self.plane.manual_signal(title, "error rate 7% since 09:12")
        assert outcome.status == 202
        return str(outcome.body["work_id"])

    async def investigating(self, title: str = "API 5xx") -> str:
        work_id = self.new_work(title)
        await self.plane.tick()
        assert self.state(work_id) == "investigating"
        return work_id

    def state(self, work_id: str) -> str:
        work = self.plane.work(work_id)
        assert work is not None
        return str(work["state"])

    def current(self, work_id: str) -> dict[str, Any]:
        detail = self.plane.detail(work_id)
        assert detail is not None and detail["current"] is not None
        return detail["current"]

    def kinds(self, work_id: str) -> list[str]:
        return [e["kind"] for e in self.plane.ledger.entries(work_id=work_id)]

    async def ready(self, plan: dict[str, Any] | None = None) -> tuple[str, dict[str, Any]]:
        work_id = await self.investigating()
        outcome = self.plane.receive_result("infra", {"work_id": work_id, "text": fenced(plan or plan_doc())})
        assert outcome.body["status"] == "plan_ready", outcome.body
        return work_id, self.current(work_id)

    async def running(self) -> tuple[str, dict[str, Any], str]:
        work_id, current = await self.ready()
        approval = self.plane.approve(
            work_id, version=current["version"], plan_hash_value=current["plan_hash"], via="web"
        )
        await self.plane.tick()
        assert self.state(work_id) == "running"
        return work_id, current, str(approval.body["approval_id"])


@pytest.fixture
def h(config_dict: dict[str, Any], env: dict[str, str]) -> Harness:
    return Harness(config_dict, env)


async def test_the_whole_path_from_signal_to_done(h: Harness) -> None:
    work_id = await h.investigating()
    sent = h.investigations[0]
    assert sent["to"] == "infra" and sent["work_id"] == work_id
    assert [w["name"] for w in sent["workers"]] == ["ops", "agent-ops"] and sent["consultable"] == ["code"]

    result = h.plane.receive_result("infra", {"work_id": work_id, "text": fenced(plan_doc()), "cost_usd": 0.12})
    assert result.body == {"status": "plan_ready", "version": 1}
    current = h.current(work_id)
    assert current["plan_hash"] == plan_hash(parse_plan(plan_doc()))
    assert [m["author"] for m in h.plane.detail(work_id)["messages"]] == ["investigator:infra"]  # type: ignore[index]

    approved = h.plane.approve(work_id, version=1, plan_hash_value=current["plan_hash"], via="web")
    assert approved.status == 200 and h.state(work_id) == "approved"
    await h.plane.tick()
    launch = h.launches[0]
    assert launch["plan"] == current["plan"] and launch["approval"]["plan_hash"] == current["plan_hash"]
    assert h.state(work_id) == "running"

    approval_id = approved.body["approval_id"]
    progress = {
        "approval_id": approval_id,
        "plan_hash": current["plan_hash"],
        "group": 1,
        "worker": "ops",
        "event": "step.end",
        "step": {
            "index": 1,
            "target": "demo/api",
            "command": "echo restarting api",
            "exit_code": 0,
            "tail": "restarting api",
        },
    }
    assert h.plane.receive_progress(progress).status == 200
    report = {
        "approval_id": approval_id,
        "plan_hash": current["plan_hash"],
        "status": "done",
        "groups": [
            {"worker": "ops", "status": "done", "record_intact": True, "record_head": "ab" * 32, "steps": [{}, {}]}
        ],
    }
    assert h.plane.receive_run_result(report).body == {"status": "recorded"}
    assert h.plane.receive_run_result(report).body == {"status": "already recorded"}
    assert h.state(work_id) == "done"
    assert h.kinds(work_id) == [
        "work.created",
        "investigation.dispatched",
        "plan.ready",
        "approval.granted",
        "run.launched",
        "run.step.end",
        "run.finished",
    ]
    assert h.plane.ledger.verify()["intact"]

    await h.plane.tick()
    events = [r.headers["X-Airlock-Event"] for r in h.hooks]
    # The first tick hands the witness a head at once; every run's end hands it another.
    assert events == [
        "work.created",
        "ledger.checkpoint",
        "plan.ready",
        "work.approved",
        "run.started",
        "run.finished",
        "ledger.checkpoint",
    ]
    for request in h.hooks:
        verify(h.env["T_HOOKS"], request.content, request.headers, now=h.clock())


async def test_an_approval_names_the_version_and_hash_you_read(h: Harness) -> None:
    work_id, current = await h.ready()
    assert (
        h.plane.approve(work_id, version=1, plan_hash_value="0" * 64, via="web").body["reason"]
        == "the plan changed since you read it"
    )
    assert h.plane.approve(work_id, version=2, plan_hash_value=current["plan_hash"], via="web").status == 409
    assert h.state(work_id) == "plan_ready"
    ok = h.plane.approve(work_id, version=1, plan_hash_value=current["plan_hash"], via="web")
    assert ok.status == 200
    again = h.plane.approve(work_id, version=1, plan_hash_value=current["plan_hash"], via="web")
    assert again.status == 409 and "approved" in again.body["reason"]


async def test_a_message_from_you_makes_a_new_version_and_the_old_one_cannot_be_approved(h: Harness) -> None:
    work_id, v1 = await h.ready()
    assert h.plane.operator_message(work_id, "do not restart during the sale; drain first", via="web").body["reopens"]
    assert h.state(work_id) == "queued"
    await h.plane.tick()
    assert h.investigations[-1]["messages"][-1]["text"].startswith("do not restart")
    assert h.investigations[-1]["latest_plan"] == v1["plan"]

    revised = plan_doc(summary="Drain, then restart the demo service")
    h.plane.receive_result("infra", {"work_id": work_id, "text": fenced(revised, "Revised: drain first.")})
    v2 = h.current(work_id)
    assert v2["version"] == 2 and v2["plan_hash"] != v1["plan_hash"]
    assert '"summary": "Drain, then restart the demo service"' in h.plane.detail(work_id)["changes"]  # type: ignore[index]
    assert h.plane.approve(work_id, version=1, plan_hash_value=v1["plan_hash"], via="web").status == 409
    assert h.plane.approve(work_id, version=2, plan_hash_value=v2["plan_hash"], via="web").status == 200


async def test_the_same_plan_sent_again_is_not_a_new_version(h: Harness) -> None:
    work_id, v1 = await h.ready()
    h.plane.operator_message(work_id, "why a restart and not a rollback?", via="web")
    await h.plane.tick()
    h.plane.receive_result("infra", {"work_id": work_id, "text": fenced(plan_doc(), "Because nothing was deployed.")})
    assert h.current(work_id)["version"] == 1 and h.state(work_id) == "plan_ready"


async def test_an_answer_without_a_plan_keeps_the_standing_plan(h: Harness) -> None:
    work_id, v1 = await h.ready()
    h.plane.operator_message(work_id, "how long will it take?", via="web")
    await h.plane.tick()
    assert (
        h.plane.receive_result("infra", {"work_id": work_id, "text": "About two minutes."}).body["status"]
        == "plan_ready"
    )
    assert h.current(work_id)["plan_hash"] == v1["plan_hash"]


async def test_a_report_with_nothing_to_do_is_answered(h: Harness) -> None:
    work_id = await h.investigating()
    assert h.plane.receive_result(
        "infra", {"work_id": work_id, "text": "A false alarm: the probe itself was down."}
    ).body == {"status": "answered"}
    assert "approve" not in h.plane.work(work_id)["actions"]  # type: ignore[index]
    assert h.plane.close(work_id, via="web").status == 200 and h.state(work_id) == "closed"


async def test_you_writing_during_an_investigation_sends_it_round_again(h: Harness) -> None:
    work_id = await h.investigating()
    assert not h.plane.operator_message(work_id, "also check the cache", via="web").body["reopens"]
    outcome = h.plane.receive_result("infra", {"work_id": work_id, "text": fenced(plan_doc())})
    assert outcome.body["status"] == "queued" and h.state(work_id) == "queued"
    await h.plane.tick()
    texts = [m["text"] for m in h.investigations[-1]["messages"]]
    assert texts == ["also check the cache", "Findings: the pool is exhausted."]
    assert (
        h.plane.receive_result("infra", {"work_id": work_id, "text": fenced(plan_doc())}).body["status"] == "plan_ready"
    )


async def test_an_invalid_plan_goes_back_once_then_stops(h: Harness) -> None:
    work_id = await h.investigating()
    bad = plan_doc(steps=[{"worker": "ops", "target": "prod", "argv": ["kubectl", "delete", "ns", "prod"]}])
    first = h.plane.receive_result("infra", {"work_id": work_id, "text": fenced(bad)})
    assert first.body["status"] == "revision_requested" and h.state(work_id) == "queued"
    await h.plane.tick()
    assert "not on worker ops's command allowlist" in h.investigations[-1]["latest_errors"][0]
    assert h.investigations[-1]["messages"][-1]["author"] == "system"
    second = h.plane.receive_result("infra", {"work_id": work_id, "text": fenced(bad)})
    assert second.body["status"] == "plan_invalid" and h.state(work_id) == "plan_invalid"
    assert h.plane.approve(work_id, version=1, plan_hash_value="x", via="web").status == 409
    stored = h.plane.detail(work_id)["plans"]  # type: ignore[index]
    assert [p["version"] for p in stored] == [2, 1] and all(p["errors"] for p in stored)


async def test_only_the_owner_speaks_for_a_work_item(h: Harness) -> None:
    work_id = await h.investigating()
    assert h.plane.receive_result("code", {"work_id": work_id, "text": fenced(plan_doc())}).status == 403
    assert (await h.plane.consult("code", {"work_id": work_id, "to": "infra", "question": "?"})).status == 403
    h.plane.receive_result("infra", {"work_id": work_id, "text": "done"})
    assert h.plane.receive_result("infra", {"work_id": work_id, "text": "again"}).status == 409


async def test_consult_is_relayed_redacted_and_bounded(h: Harness) -> None:
    work_id = await h.investigating()
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    h.consult_answer = f"the deploy used key {key}"
    answer = await h.plane.consult("infra", {"work_id": work_id, "to": "code", "question": "what changed at 09:10?"})
    assert answer.status == 200 and key not in answer.body["answer"] and answer.body["flags"] == ["aws access key id"]
    assert (await h.plane.consult("infra", {"work_id": work_id, "to": "code", "question": "and then?"})).status == 200
    assert (await h.plane.consult("infra", {"work_id": work_id, "to": "code", "question": "a third?"})).status == 429
    assert (await h.plane.consult("infra", {"work_id": work_id, "to": "infra", "question": "me?"})).status == 403
    assert h.kinds(work_id).count("consult.answered") == 2


async def test_code_may_not_consult_anyone(h: Harness) -> None:
    work_id = h.new_work("from web")
    h.plane.db.execute("UPDATE work_items SET investigator = 'code', state = 'investigating' WHERE id = ?", [work_id])
    refused = await h.plane.consult("code", {"work_id": work_id, "to": "infra", "question": "?"})
    assert refused.status == 403 and h.kinds(work_id)[-1] == "consult.refused"


async def test_an_unused_approval_expires_back_to_a_decision(h: Harness) -> None:
    h.launch_answer = (409, {"reason": "busy: demo/api is being changed by approval other"})
    work_id, current = await h.ready()
    h.plane.approve(work_id, version=1, plan_hash_value=current["plan_hash"], via="web")
    await h.plane.tick()
    assert h.state(work_id) == "approved" and "busy" in h.plane.work(work_id)["note"]  # type: ignore[index]
    h.clock.now += 3601
    await h.plane.tick()
    assert h.state(work_id) == "plan_ready"
    assert h.plane.db.one("SELECT status FROM approvals")["status"] == "expired"  # type: ignore[index]
    launches = len(h.launches)
    h.clock.now += 60
    await h.plane.tick()
    assert len(h.launches) == launches


async def test_busy_then_free_launches_on_retry(h: Harness) -> None:
    h.launch_answer = (409, {"reason": "busy: demo/api is being changed by approval other"})
    work_id, current = await h.ready()
    h.plane.approve(work_id, version=1, plan_hash_value=current["plan_hash"], via="web")
    await h.plane.tick()
    h.launch_answer = (202, {"status": "accepted"})
    await h.plane.tick()
    assert h.state(work_id) == "approved"
    h.clock.now += 31
    await h.plane.tick()
    assert h.state(work_id) == "running"


async def test_a_launcher_refusal_is_final_and_recorded(h: Harness) -> None:
    h.launch_answer = (422, {"reason": "the launcher's own worker profiles do not allow this plan: ..."})
    work_id, current = await h.ready()
    h.plane.approve(work_id, version=1, plan_hash_value=current["plan_hash"], via="web")
    await h.plane.tick()
    assert h.state(work_id) == "refused" and h.kinds(work_id)[-1] == "run.refused"


async def test_already_launched_means_it_is_running(h: Harness) -> None:
    h.launch_answer = (409, {"reason": "already launched: an approval starts one run"})
    work_id, current = await h.ready()
    h.plane.approve(work_id, version=1, plan_hash_value=current["plan_hash"], via="web")
    await h.plane.tick()
    assert h.state(work_id) == "running"


async def test_revoke_before_launch_and_cancel_after(h: Harness) -> None:
    h.launch_answer = (409, {"reason": "busy: held"})
    work_id, current = await h.ready()
    h.plane.approve(work_id, version=1, plan_hash_value=current["plan_hash"], via="web")
    assert h.plane.revoke(work_id, via="web").status == 200 and h.state(work_id) == "plan_ready"
    h.clock.now += 60
    h.launch_answer = (202, {"status": "accepted"})
    await h.plane.tick()
    assert [launch["path"] for launch in h.launches] == []

    work_id, current, approval_id = await h.running()
    assert h.plane.revoke(work_id, via="web").status == 409
    assert (await h.plane.cancel(work_id, via="web")).status == 200
    assert h.launches[-1] == {"path": "/cancel", "approval_id": approval_id}
    h.plane.receive_run_result(
        {"approval_id": approval_id, "plan_hash": current["plan_hash"], "status": "cancelled", "groups": []}
    )
    assert h.state(work_id) == "cancelled"


async def test_reports_for_another_plan_are_refused(h: Harness) -> None:
    work_id, current, approval_id = await h.running()
    wrong = {"approval_id": approval_id, "plan_hash": "f" * 64, "status": "done"}
    assert h.plane.receive_run_result(wrong).status == 409
    assert h.plane.receive_progress({**wrong, "event": "step.end"}).status == 409
    assert h.plane.receive_run_result({"approval_id": "nope", "plan_hash": current["plan_hash"]}).status == 404
    assert h.state(work_id) == "running"


async def test_adapters_speak_only_for_mapped_users(h: Harness) -> None:
    work_id, current = await h.ready()
    decision = {"work_id": work_id, "decision": "approve", "version": 1, "plan_hash": current["plan_hash"]}
    assert h.plane.adapter_decision("chat", {**decision, "platform_user": "u-999"}).status == 403
    assert h.plane.ledger.entries()[0]["kind"] == "adapter.identity_refused"
    assert h.plane.adapter_decision("chat", {**decision, "platform_user": "u-123"}).status == 200
    approval = h.plane.db.one("SELECT approver, via FROM approvals")
    assert approval == {"approver": "operator", "via": "adapter:chat"}

    other, _ = await h.ready()
    message = {"work_id": other, "platform_user": "u-123", "text": "use the canary first"}
    assert h.plane.adapter_message("chat", message).body["reopens"]
    assert h.plane.adapter_decision(
        "chat", {"work_id": other, "platform_user": "u-123", "decision": "maybe"}
    ).status in (400, 409)


async def test_an_unreachable_investigator_is_retried_then_an_error(h: Harness) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    h.router.handle("infra", down)
    work_id = h.new_work()
    for delay in DISPATCH_BACKOFF_SECONDS[:-1]:
        await h.plane.tick()
        assert h.state(work_id) == "queued"
        h.clock.now += delay
    await h.plane.tick()
    assert h.state(work_id) == "error" and "unreachable" in h.plane.work(work_id)["note"]  # type: ignore[index]
    assert h.plane.operator_message(work_id, "try again", via="web").body["reopens"]


async def test_notifications_retry_then_go_dead(h: Harness) -> None:
    h.router.handle("hooks", lambda request: httpx.Response(500))
    h.new_work()
    for _ in range(MAX_ATTEMPTS):
        await h.plane.outbox.deliver_due(h.plane.client, now=h.clock.now)
        h.clock.now += 700
    row = h.plane.db.one("SELECT status, attempts, last_error FROM outbox")
    assert row == {"status": "dead", "attempts": MAX_ATTEMPTS, "last_error": "HTTP 500"}


def test_detail_lists_actions_by_state(config_dict: dict[str, Any], env: dict[str, str]) -> None:
    config = copy.deepcopy(config_dict)
    plane = ControlPlane(load_control(config, env))
    work_id = plane.manual_signal("t", "b").body["work_id"]
    assert plane.work(work_id)["actions"] == ("message", "close")  # type: ignore[index]


async def test_an_investigation_that_never_reports_back_becomes_an_error(h: Harness) -> None:
    work_id = await h.investigating()
    h.clock.now += 3599
    await h.plane.tick()
    assert h.state(work_id) == "investigating"
    h.clock.now += 2
    await h.plane.tick()
    assert h.state(work_id) == "error" and h.kinds(work_id)[-1] == "investigation.timed_out"
    assert h.plane.receive_result("infra", {"work_id": work_id, "text": "late"}).status == 409


async def test_a_report_quoting_json_is_a_report(h: Harness) -> None:
    work_id = await h.investigating()
    report = 'Pods look fine:\n\n```json\n{"items": [{"name": "api-1", "ready": true}]}\n```'
    assert h.plane.receive_result("infra", {"work_id": work_id, "text": report}).body == {"status": "answered"}
    assert '"api-1"' in h.plane.detail(work_id)["messages"][-1]["text"]  # type: ignore[index]


async def test_the_dispatch_says_what_to_do_with_the_session(h: Harness) -> None:
    work_id = await h.investigating()
    assert h.investigations[-1]["session"] == {"mode": "resume"}
    h.plane.receive_result("infra", {"work_id": work_id, "text": "a report", "session": "sess-1"})
    assert h.plane.work(work_id)["engine_session"] == "sess-1"  # type: ignore[index]
    assert h.plane.fresh(work_id, via="web").status == 200
    await h.plane.tick()
    assert h.investigations[-1]["session"] == {"mode": "fresh"}
    assert "Starting over" not in str(h.investigations[-1])  # the prompt is the node's job; the directive is ours
    h.plane.receive_result("infra", {"work_id": work_id, "text": "a second report"})
    h.plane.operator_message(work_id, "and the cache?", via="web")
    await h.plane.tick()
    assert h.investigations[-1]["session"] == {"mode": "resume"}, "a fresh start happens once, then the item resumes"
    assert h.kinds(work_id).count("investigation.fresh") == 1


async def test_a_sequel_is_dispatched_as_a_fork_with_what_came_before(h: Harness) -> None:
    work_id, current = await h.ready()
    h.plane.reject(work_id, via="web", reason="not during the sale")
    signal = {
        "source": "web",
        "event": "manual",
        "title": "API 5xx",
        "body": "again",
        "url": "",
        "key": "k1",
        "labels": [],
    }
    h.plane.db.execute("UPDATE work_items SET key = 'k1' WHERE id = ?", [work_id])
    previous = h.plane._concluded_with_key("web", "k1", 21600, "infra")
    assert previous is not None and previous["id"] == work_id
    sequel = h.plane.create_work(signal, "infra", actor="test", continues=previous)
    await h.plane.tick()
    sent = h.investigations[-1]
    assert sent["work_id"] == sequel and sent["session"] == {"mode": "fork", "from": work_id}
    assert sent["continues"]["state"] == "rejected" and sent["continues"]["plan_summary"] == current["plan"]["summary"]
    detail = h.plane.detail(work_id)
    assert detail is not None and [c["id"] for c in detail["continued_by"]] == [sequel]


async def test_fresh_is_offered_only_where_it_makes_sense(h: Harness) -> None:
    work_id, _, _ = await h.running()
    assert h.plane.fresh(work_id, via="web").status == 409
    assert h.plane.fresh("nope", via="web").status == 404


def test_a_notification_carries_the_report_s_first_paragraph_masked() -> None:
    from airlock.control.service import lead_of

    report = (
        "## Findings\n\nTwo config lines and a restart. Token AKIAABCDEFGHIJKLMNOP was in the log.\n\nDetails below."
    )
    lead = lead_of(report)
    assert lead.startswith("Two config lines and a restart.")  # the heading alone is skipped
    assert "AKIAABCDEFGHIJKLMNOP" not in lead
    assert "AKIAABCDEFGHIJKLMNOP" not in lead_of("Two config lines. Token AKIAABCDEFGHIJKLMNOP was in the log.")
    assert lead_of("") == ""
