"""The sandbox rule: a plan that runs only on sandbox workers is approved without your click, and checked like yours.

What the rule may approve is decided three times: by the profile's shape when the
configuration loads; by the control plane (every step on a sandbox worker, once
per version, within each worker's allowance); and by the launcher from its own
side (its own profiles, a container, nothing but the model's settings in the
credentials, an internal network, its own count of the allowance).
"""

from __future__ import annotations

import copy
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from airlock.config import ConfigError, load_control, load_launcher
from airlock.control.app import create_app
from airlock.control.service import ControlPlane
from airlock.extras.feishu.render import for_event
from airlock.launcher.app import create_launcher_app
from airlock.launcher.runtime import DockerRuntime, LocalRuntime, Runtime
from airlock.launcher.sandbox import credentials_problem
from airlock.launcher.service import Launcher
from airlock.plans import SANDBOX_APPROVER
from airlock.runner.investigator import investigation_prompt
from airlock.runner.recorder import read_lines
from tests.conftest import Router, body_of, fenced, plan_doc
from tests.test_control_flow import Harness
from tests.test_launcher import Control, approval_for
from tests.test_web import login
from tests.test_workspace import git, mirror

pytestmark = pytest.mark.anyio

CODER = {
    "name": "coder",
    "modes": ["task"],
    "repos": {"demo": "/nowhere/demo"},
    "allowed_permissions": ["repo:commit"],
    "approval": "sandbox",
    "sandbox_runs_per_day": 2,
}
FIX = "$ printf 'def add(a, b):\\n    return a + b\\n' > calc.py\n$ git commit -qam 'fix add'"


def coder_plan(task: str = "fix add", **overrides: Any) -> dict[str, Any]:
    plan: dict[str, Any] = {
        "summary": "Fix add()",
        "permissions": {"coder": ["repo:commit"]},
        "steps": [{"worker": "coder", "target": "repo:demo", "task": task}],
    }
    plan.update(overrides)
    return plan_doc(**plan)


def with_coder(config_dict: dict[str, Any], change: Callable[[dict[str, Any]], Any] | None = None) -> dict[str, Any]:
    config = copy.deepcopy(config_dict)
    coder = copy.deepcopy(CODER)
    if change is not None:
        change(coder)
    config["workers"] = [*config["workers"], coder]
    return config


class PretendContainer(LocalRuntime):
    """The local runtime claiming to be a container, so the launcher's checks of the rule run without Docker."""

    isolation = "container"

    def __init__(self, network: str | None = None) -> None:
        super().__init__()
        self.network = network

    async def network_problem(self, network: str | None) -> str | None:
        return self.network


def notifications(h: Harness, event: str) -> list[dict[str, Any]]:
    return [body_of(r)["payload"] for r in h.hooks if body_of(r)["event"] == event]


def rule(plan: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    return approval_for(plan, **{"approver": SANDBOX_APPROVER, "via": "rule", **overrides})


def launcher_for(
    config: dict[str, Any], env: dict[str, str], runtime: Runtime, **kwargs: Any
) -> tuple[Launcher, Control]:
    control = Control(env["T_LAUNCHER"])
    router = Router()
    router.handle("control", control)
    launcher = Launcher(
        load_launcher(config, env), runtime, client=httpx.AsyncClient(transport=router), engine="stub", **kwargs
    )
    return launcher, control


@pytest.fixture
def h(config_dict: dict[str, Any], env: dict[str, str]) -> Harness:
    return Harness(with_coder(config_dict), env)


# ---------------------------------------------------------------------- the profile


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda w: w.update(repos={}), "needs repos"),
        (lambda w: w.update(env={"GITHUB_TOKEN": "not-a-real-token"}), "could carry a credential"),
        (lambda w: w.update(env={"HTTPS_PROXY": "http://me:pw@egress:8888"}), "has credentials in it"),
        (lambda w: w.update(network="host"), "not host"),
        (lambda w: w.update(sandbox_runs_per_day=0), "between 1 and 1000"),
        (lambda w: w.update(approval="auto"), "approval must be one of"),
    ],
)
def test_only_a_profile_that_shows_a_sandbox_may_ask_for_the_rule(
    config_dict: dict[str, Any], env: dict[str, str], change: Callable[[dict[str, Any]], Any], message: str
) -> None:
    with pytest.raises(ConfigError, match=message):
        load_control(with_coder(config_dict, change), env)
    with pytest.raises(ConfigError, match=message):
        load_launcher(with_coder(config_dict, change), env)


def test_the_allowance_belongs_to_the_rule(config_dict: dict[str, Any], env: dict[str, str]) -> None:
    config = with_coder(config_dict, lambda w: w.pop("sandbox_runs_per_day"))
    workers = load_control(config, env).workers
    assert workers["coder"].sandbox_runs_per_day == 10 and workers["ops"].approval == "operator"
    config["workers"][0]["sandbox_runs_per_day"] = 3  # ops: its plans are yours
    with pytest.raises(ConfigError, match="is for approval: sandbox"):
        load_launcher(config, env)


# ---------------------------------------------------------------------- the control plane


async def test_a_plan_only_on_sandbox_workers_is_approved_by_the_rule_and_launched_as_such(h: Harness) -> None:
    work_id = await h.investigating()
    sent = h.investigations[-1]
    assert {"name": "coder", "approval": "sandbox", "repos": ["demo"]}.items() <= sent["workers"][-1].items()
    prompt = investigation_prompt(sent)
    assert "a step's target is one of: repo:demo" in prompt and "a sandbox worker" in prompt

    outcome = h.plane.receive_result("infra", {"work_id": work_id, "text": fenced(coder_plan())})
    assert outcome.body == {"status": "approved", "version": 1} and h.state(work_id) == "approved"
    approval = h.plane.db.one("SELECT * FROM approvals WHERE work_id = ?", [work_id])
    assert approval is not None and approval["approver"] == SANDBOX_APPROVER and approval["via"] == "rule"
    granted = [e for e in h.plane.ledger.entries(work_id=work_id) if e["kind"] == "approval.granted"]
    assert granted[0]["actor"] == SANDBOX_APPROVER and granted[0]["data"]["plan_hash"] == approval["plan_hash"]

    await h.plane.tick()
    assert h.state(work_id) == "running"
    assert h.launches[-1]["approval"]["approver"] == SANDBOX_APPROVER
    ready = notifications(h, "plan.ready")[-1]
    assert ready["approved_by"] == SANDBOX_APPROVER and ready["state"] == "approved"
    assert notifications(h, "run.started")[-1]["approved_by"] == SANDBOX_APPROVER


async def test_one_step_on_any_other_worker_makes_the_plan_yours(h: Harness) -> None:
    mixed = coder_plan(
        permissions={"coder": ["repo:commit"], "ops": ["svc:restart"]},
        steps=[
            {"worker": "coder", "target": "repo:demo", "task": "fix add"},
            {"worker": "ops", "target": "demo/api", "argv": ["echo", "restarting", "api"]},
        ],
    )
    work_id, _ = await h.ready(mixed)
    assert h.plane.db.all("SELECT * FROM approvals WHERE work_id = ?", [work_id]) == []
    await h.plane.tick()
    ready = notifications(h, "plan.ready")[-1]
    assert "approved_by" not in ready and "rule_declined" not in ready


async def test_the_rule_approves_a_version_once_and_a_worker_within_its_allowance(h: Harness) -> None:
    first = await h.investigating("one")
    h.plane.receive_result("infra", {"work_id": first, "text": fenced(coder_plan())})
    await h.plane.tick()
    approval = h.launches[-1]["approval"]
    h.plane.receive_run_result(
        {"approval_id": approval["id"], "plan_hash": approval["plan_hash"], "status": "done", "groups": []}
    )
    # Asked about it afterwards, the investigator sends the same plan again: running it twice is your call.
    h.plane.operator_message(first, "why this fix?", via="web")
    await h.plane.tick()
    again = h.plane.receive_result("infra", {"work_id": first, "text": fenced(coder_plan(), "Because add subtracts.")})
    assert again.body["status"] == "plan_ready"
    await h.plane.tick()
    assert notifications(h, "plan.ready")[-1]["rule_declined"] == "approved_once"

    second = await h.investigating("two")
    result = h.plane.receive_result("infra", {"work_id": second, "text": fenced(coder_plan("fix sub"))})
    assert result.body["status"] == "approved"
    third = await h.investigating("three")
    result = h.plane.receive_result("infra", {"work_id": third, "text": fenced(coder_plan("fix mul"))})
    assert result.body["status"] == "plan_ready"
    assert "sandbox approvals of the last 24 hours" in str(h.plane.work(third)["note"])  # type: ignore[index]
    assert "approval.rule_declined" in h.kinds(third)
    await h.plane.tick()
    ready = notifications(h, "plan.ready")[-1]
    assert ready["rule_declined"] == "allowance" and ready["allowance"] == {"worker": "coder", "used": 2, "limit": 2}

    h.clock.now += 86401  # a day later the allowance is back
    fourth = await h.investigating("four")
    result = h.plane.receive_result("infra", {"work_id": fourth, "text": fenced(coder_plan("fix div"))})
    assert result.body["status"] == "approved"


async def test_a_rule_approval_can_be_taken_back_and_then_the_plan_is_yours(h: Harness) -> None:
    work_id = await h.investigating()
    h.plane.receive_result("infra", {"work_id": work_id, "text": fenced(coder_plan())})
    assert h.plane.revoke(work_id, via="web").ok and h.state(work_id) == "plan_ready"
    await h.plane.tick()
    assert h.launches == [] and h.state(work_id) == "plan_ready"
    current = h.current(work_id)
    assert h.plane.approve(work_id, version=current["version"], plan_hash_value=current["plan_hash"], via="web").ok
    rows = h.plane.db.all("SELECT approver, status FROM approvals WHERE work_id = ? ORDER BY rowid", [work_id])
    assert [(r["approver"], r["status"]) for r in rows] == [(SANDBOX_APPROVER, "revoked"), ("operator", "approved")]


async def test_the_report_keeps_what_the_rule_ran_apart_from_what_you_ran(h: Harness) -> None:
    ruled = await h.investigating()
    h.plane.receive_result("infra", {"work_id": ruled, "text": fenced(coder_plan())})
    await h.plane.tick()
    approval = h.launches[-1]["approval"]
    h.plane.receive_run_result(
        {"approval_id": approval["id"], "plan_hash": approval["plan_hash"], "status": "done", "groups": []}
    )
    yours, current, mine = await h.running()
    h.plane.receive_run_result({"approval_id": mine, "plan_hash": current["plan_hash"], "status": "done", "groups": []})
    report = h.plane.report(7)
    by_id = {r["id"]: r for r in report["items"]}
    assert by_id[ruled]["outcome"] == "ran_in_sandbox" and by_id[yours]["outcome"] == "acted_on"
    assert report["approvals"]["by_rule"] == 1 and report["approvals"]["count"] == 1


# ---------------------------------------------------------------------- the launcher


async def test_the_launcher_honours_the_rule_only_where_its_own_side_agrees(
    config_dict: dict[str, Any], env: dict[str, str], tmp_path: Path
) -> None:
    plan = coder_plan()
    # Its own profile says you approve this worker: the control plane's word is not enough.
    drifted = with_coder(config_dict, lambda w: (w.update(approval="operator"), w.pop("sandbox_runs_per_day")))
    launcher, _ = launcher_for(drifted, env, PretendContainer())
    await launcher.inspect_sandbox()
    refused = launcher.accept(rule(plan))
    assert refused.status == 422 and "not a sandbox worker in the launcher's own profiles" in refused.body["reason"]
    assert read_lines(Path(launcher.config.runs_dir) / "refusals.jsonl")[-1]["data"]["reason"] == refused.body["reason"]
    await launcher.close()

    launcher, _ = launcher_for(with_coder(config_dict), env, PretendContainer())
    refused = launcher.accept(rule(plan))
    assert refused.status == 422 and "was not inspected when the launcher started" in refused.body["reason"]
    await launcher.inspect_sandbox()
    unknown = launcher.accept(rule(plan, approver="policy:yolo"))
    assert unknown.status == 422 and "does not know" in unknown.body["reason"]
    await launcher.close()

    launcher, _ = launcher_for(with_coder(config_dict), env, LocalRuntime())
    await launcher.inspect_sandbox()
    refused = launcher.accept(rule(plan))
    assert refused.status == 422 and "isolates nothing" in refused.body["reason"]
    await launcher.close()

    launcher, _ = launcher_for(with_coder(config_dict), env, PretendContainer("its network x is not internal"))
    assert await launcher.inspect_sandbox() == {"coder": "its network x is not internal"}
    refused = launcher.accept(rule(plan))
    assert refused.status == 422 and "is marked sandbox, but its network x is not internal" in refused.body["reason"]
    await launcher.close()

    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "engine.env").write_text("AIRLOCK_MODEL=m\n")
    (creds / "aws-credentials").write_text("[default]\n")
    holding = with_coder(config_dict, lambda w: w.update(credentials_dir=str(creds)))
    launcher, _ = launcher_for(holding, env, PretendContainer())
    await launcher.inspect_sandbox()
    refused = launcher.accept(rule(plan))
    assert refused.status == 422 and "holds aws-credentials besides engine.env" in refused.body["reason"]
    await launcher.close()


def test_a_sandbox_worker_s_credentials_are_its_model_s_settings_and_nothing_else(tmp_path: Path) -> None:
    creds = tmp_path / "creds"
    creds.mkdir()
    assert credentials_problem(None) is None and credentials_problem(str(creds)) is None
    (creds / "engine.env").write_text(
        "# the model\nANTHROPIC_BASE_URL=https://model.invalid\nANTHROPIC_AUTH_TOKEN=not-a-real-key\n"
        "AIRLOCK_MODEL=m\nCLAUDE_CODE_SUBAGENT_MODEL=m\nAPI_TIMEOUT_MS=60000\nDISABLE_TELEMETRY=1\n"
    )
    assert credentials_problem(str(creds)) is None
    (creds / "engine.env").write_text("AIRLOCK_MODEL=m\nGITHUB_TOKEN=not-a-real-token\nexport AWS_PROFILE=x\n")
    problem = credentials_problem(str(creds)) or ""
    assert "sets GITHUB_TOKEN, export AWS_PROFILE, which is not a model setting" in problem
    (creds / "engine.env").write_text("AIRLOCK_MODEL=m\n")
    (creds / "kubeconfig").write_text("apiVersion: v1\n")
    assert "holds kubeconfig besides engine.env" in (credentials_problem(str(creds)) or "")
    (creds / "kubeconfig").unlink()
    (creds / "engine.env").unlink()
    (tmp_path / "elsewhere.env").write_text("AIRLOCK_MODEL=m\n")
    (creds / "engine.env").symlink_to(tmp_path / "elsewhere.env")
    assert "is not a plain file" in (credentials_problem(str(creds)) or "")
    assert "cannot be read" in (credentials_problem(str(tmp_path / "missing")) or "")


async def test_the_launcher_keeps_its_own_count_and_runs_what_the_rule_approved(
    config_dict: dict[str, Any], env: dict[str, str], tmp_path: Path
) -> None:
    source = mirror(tmp_path)
    start = git(source, "rev-parse", "HEAD").strip()
    config = with_coder(config_dict, lambda w: w.update(repos={"demo": str(source)}, sandbox_runs_per_day=1))
    launcher, control = launcher_for(config, env, PretendContainer())
    await launcher.inspect_sandbox()
    plan = coder_plan(FIX)
    assert launcher.accept(rule(plan)).status == 202
    await launcher.drain()
    result = control.results[0]
    assert result["status"] == "done", result
    assert "+    return a + b" in result["groups"][0]["workspace"]["patch"]
    assert git(source, "rev-parse", "HEAD").strip() == start
    recorded = json.loads((Path(launcher.config.runs_dir) / "ap1" / "approval.json").read_text())
    assert recorded["approver"] == SANDBOX_APPROVER

    again = launcher.accept(rule(plan, id="ap2"))
    assert again.status == 422 and "its allowance is 1" in again.body["reason"]
    # Your approvals are neither counted against the allowance nor stopped by it.
    assert launcher.accept(approval_for(plan, id="ap3")).status == 202
    await launcher.drain()
    assert [r["status"] for r in control.results] == ["done", "done"]
    await launcher.close()


async def test_docker_says_whether_a_network_reaches_more_than_its_proxy(tmp_path: Path) -> None:
    calls = tmp_path / "calls.jsonl"
    fake = tmp_path / "docker"
    fake.write_text(
        f"#!{sys.executable}\nimport json, sys\n"
        f"open({str(calls)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "answers = {'airlock_egress': 'true', 'airlock_outside': 'false'}\n"
        "if sys.argv[-1] not in answers:\n    sys.exit(1)\n"
        "print(answers[sys.argv[-1]])\n"
    )
    fake.chmod(0o755)
    runtime = DockerRuntime(str(fake))
    assert await runtime.network_problem(None) is None and await runtime.network_problem("none") is None
    assert await runtime.network_problem("airlock_egress") is None
    assert "is not internal" in (await runtime.network_problem("airlock_outside") or "")
    assert "does it exist" in (await runtime.network_problem("gone") or "")
    first = json.loads(calls.read_text().splitlines()[0])
    assert first == ["network", "inspect", "--format", "{{.Internal}}", "airlock_egress"]


async def test_signal_to_diff_with_no_click(config_dict: dict[str, Any], env: dict[str, str], tmp_path: Path) -> None:
    """The whole path in one process, real HTTP between the control plane and the launcher, and nobody approving."""
    source = mirror(tmp_path)
    start = git(source, "rev-parse", "HEAD").strip()
    config = with_coder(config_dict, lambda w: w.update(repos={"demo": str(source)}))
    h = Harness(config, env)
    launcher_router = Router()
    launcher = Launcher(
        load_launcher(config, env),
        PretendContainer(),
        client=httpx.AsyncClient(transport=launcher_router),
        clock=h.clock,
        engine="stub",
    )
    await launcher.inspect_sandbox()
    launcher_router.mount("control", create_app(h.plane.config, plane=h.plane, run_loop=False))
    h.router.handlers.pop("launcher")
    h.router.mount("launcher", create_launcher_app(launcher, run_loop=False))

    work_id = await h.investigating()
    h.plane.receive_result("infra", {"work_id": work_id, "text": fenced(coder_plan(FIX))})
    await h.plane.tick()  # the rule's approval reaches the real launcher, which checks it and starts
    await launcher.drain()  # the worker commits in its fresh clone; the launcher computes the change and reports
    assert h.state(work_id) == "done"
    kinds = h.kinds(work_id)
    assert kinds.index("approval.granted") < kinds.index("run.launched") < kinds.index("run.finished")
    await h.plane.tick()
    finished = notifications(h, "run.finished")[-1]
    workspace = finished["groups"][0]["workspace"]
    assert finished["approved_by"] == SANDBOX_APPROVER and workspace["repo"] == "demo"
    assert (workspace["files_changed"], workspace["insertions"], workspace["deletions"]) == (1, 1, 1)
    assert git(source, "rev-parse", "HEAD").strip() == start
    await launcher.close()


# ---------------------------------------------------------------------- what you see


def test_the_work_page_says_the_rule_approved_it(config_dict: dict[str, Any], env: dict[str, str]) -> None:
    plane = ControlPlane(load_control(with_coder(config_dict), env))
    work_id = str(plane.manual_signal("add() subtracts", "calc.py line 2").body["work_id"])
    plane.db.execute("UPDATE work_items SET state = 'investigating' WHERE id = ?", [work_id])
    assert (
        plane.receive_result("infra", {"work_id": work_id, "text": fenced(coder_plan())}).body["status"] == "approved"
    )
    client = TestClient(create_app(plane.config, plane=plane, run_loop=False), follow_redirects=False)
    login(client)
    page = client.get(f"/work/{work_id}").text
    assert "这一版由<strong>沙箱规则</strong>批准" in page and "<td>沙箱规则</td>" in page
    assert "批准 v1 并执行" not in page


def test_a_card_says_what_the_rule_did_and_what_is_left_to_you() -> None:
    base = {"work_id": "w1", "title": "add() subtracts", "link": "http://control/work/w1", "version": 1}
    plan = {**base, "summary": "Fix add()", "risk": "low", "lead": "add() subtracts."}
    running = for_event("plan.ready", {**plan, "approved_by": SANDBOX_APPROVER}) or {}
    assert running["header"]["title"]["content"] == "沙箱里自动执行 v1：add() subtracts"
    assert "看方案并批准" not in json.dumps(running, ensure_ascii=False)
    allowance = {"worker": "coder", "used": 2, "limit": 2}
    waiting = json.dumps(
        for_event("plan.ready", {**plan, "rule_declined": "allowance", "allowance": allowance}), ensure_ascii=False
    )
    assert "过去 24 小时已由规则批准 2 次（上限 2），这一版等你批准" in waiting and "看方案并批准" in waiting
    groups = [{"worker": "coder", "status": "done", "workspace": {"repo": "demo", "files_changed": 1}}]
    done = for_event("run.finished", {**base, "status": "done", "groups": groups, "approved_by": SANDBOX_APPROVER})
    assert (done or {})["header"]["title"]["content"] == "沙箱跑完，待你审 diff：add() subtracts"
    assert '"content": "审 diff"' in json.dumps(done, ensure_ascii=False)
    yours = for_event("run.finished", {**base, "status": "done", "groups": groups}) or {}
    assert yours["header"]["title"]["content"] == "执行完成：add() subtracts"
