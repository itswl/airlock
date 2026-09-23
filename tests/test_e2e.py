"""The whole system in one process: pipe → investigator (consulting another) → your one click → launcher → worker → record.

Every hop is real HTTP between the real apps, signed as in production. The
only substitutes are the stub engine (no model) and the local runtime (no
Docker), and the local runtime says so in the record.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest

from airlock.config import load_control, load_launcher
from airlock.control.app import create_app
from airlock.control.service import ControlPlane
from airlock.crypto import sign, verify
from airlock.launcher.app import create_launcher_app
from airlock.launcher.runtime import LocalRuntime
from airlock.launcher.service import Launcher
from airlock.runner.engine import EngineRequest, StubEngine, StubTurn
from airlock.runner.investigator import InvestigatorNode, NodeConfig, create_node_app
from airlock.runner.recorder import read_lines, verify_lines
from tests.conftest import PASSWORD, Router, fenced, plan_doc

pytestmark = pytest.mark.anyio


def infra_script(request: EngineRequest) -> StubTurn:
    messages = [m["text"] for m in request.context.get("messages") or [] if m["author"] == "operator"]
    if any("drain" in m for m in messages):
        revised = plan_doc(
            summary="Drain, then restart the demo service",
            steps=[
                {"worker": "ops", "target": "demo/api", "argv": ["echo", "draining", "api"], "why": "you asked"},
                {
                    "worker": "ops",
                    "target": "demo/api",
                    "argv": ["echo", "restarting", "api"],
                    "why": "clears the pool",
                },
            ],
        )
        return StubTurn(text=fenced(revised, "Revised: drain first, as you asked."))
    return StubTurn(
        consults=[("code", "Did anything deploy around 09:10?")],
        tools=[
            ("Bash", {"command": "kubectl -n prod get pods"}),
            ("Bash", {"command": "kubectl -n prod delete pod api-1"}),
        ],
        text=lambda t: fenced(plan_doc(evidence=t.answers[0]), f"Pool exhausted. code says: {t.answers[0]}"),
    )


def code_script(request: EngineRequest) -> StubTurn:
    return StubTurn(text="Yes: the 09:10 deploy halved the connection pool.")


class System:
    def __init__(
        self,
        tmp_path: Path,
        config_dict: dict[str, Any],
        env: dict[str, str],
        launcher_workers: list[Any] | None = None,
    ) -> None:
        self.env = env
        self.hooks: list[httpx.Request] = []
        control_router, node_router, launcher_router = Router(), Router(), Router()

        self.plane = ControlPlane(load_control(config_dict, env), client=httpx.AsyncClient(transport=control_router))
        self.control_app = create_app(self.plane.config, plane=self.plane, run_loop=False)

        self.nodes = {}
        for name, script in (("infra", infra_script), ("code", code_script)):
            settings = NodeConfig(
                profile=name,
                secret=env[f"T_{name.upper()}"],
                control_url="http://control",
                engine="stub",
                workdir=tmp_path / name,
            )
            self.nodes[name] = InvestigatorNode(
                settings, StubEngine(script), client=httpx.AsyncClient(transport=node_router)
            )
            control_router.mount(name, create_node_app(self.nodes[name]))

        launcher_config = copy.deepcopy(config_dict)
        if launcher_workers is not None:
            launcher_config["workers"] = launcher_workers
        self.launcher = Launcher(
            load_launcher(launcher_config, env),
            LocalRuntime(),
            client=httpx.AsyncClient(transport=launcher_router),
            engine="stub",
        )
        control_router.mount("launcher", create_launcher_app(self.launcher, run_loop=False))
        control_router.handle("hooks", self._hook)
        node_router.mount("control", self.control_app)
        launcher_router.mount("control", self.control_app)
        self.web = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.control_app), base_url="http://control")

    def _hook(self, request: httpx.Request) -> httpx.Response:
        verify(self.env["T_HOOKS"], request.content, request.headers)
        self.hooks.append(request)
        return httpx.Response(200)

    async def settle(self) -> None:
        """Run the loops until nothing is left moving."""
        for _ in range(6):
            await self.plane.tick()
            for node in self.nodes.values():
                await node.drain()
            await self.launcher.drain()

    async def alert(self) -> str:
        body = json.dumps(
            {
                "status": "firing",
                "alertname": "HighErrorRate",
                "summary": "5xx over 5%",
                "description": "api since 09:12",
                "fingerprint": "fp-1",
            }
        ).encode()
        response = await self.web.post("/v1/intake/alerts", content=body, headers=sign(self.env["T_ALERTS"], body))
        assert response.status_code == 202, response.text
        return str(response.json()["work_id"])

    async def login(self) -> None:
        response = await self.web.post("/login", data={"password": PASSWORD})
        assert response.status_code == 303

    async def page(self, work_id: str) -> tuple[str, str, str, str]:
        html = (await self.web.get(f"/work/{work_id}")).text
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', html)
        digest = re.search(r'name="plan_hash" value="([0-9a-f]+)"', html)
        version = re.search(r'name="version" value="([0-9]+)"', html)
        assert csrf
        return html, csrf.group(1), digest.group(1) if digest else "", version.group(1) if version else ""

    async def close(self) -> None:
        await self.web.aclose()
        await self.launcher.close()


async def test_signal_to_record_with_one_click(
    tmp_path: Path, config_dict: dict[str, Any], env: dict[str, str]
) -> None:
    system = System(tmp_path, config_dict, env)
    work_id = await system.alert()
    await system.settle()
    assert system.plane.work(work_id)["state"] == "plan_ready"  # type: ignore[index]

    await system.login()
    html, csrf, digest_v1, version = await system.page(work_id)
    assert version == "1" and "the 09:10 deploy halved the connection pool" in html

    # Talk it over instead of approving: the investigator revises, and the new version is what gets approved.
    await system.web.post(f"/work/{work_id}/message", data={"text": "drain first, please", "csrf": csrf})
    await system.settle()
    html, csrf, digest_v2, version = await system.page(work_id)
    assert version == "2" and digest_v2 != digest_v1 and "draining" in html
    stale = await system.web.post(
        f"/work/{work_id}/approve", data={"version": "1", "plan_hash": digest_v1, "csrf": csrf}
    )
    assert stale.status_code == 303 and system.plane.work(work_id)["state"] == "plan_ready"  # type: ignore[index]

    # The one click.
    await system.web.post(f"/work/{work_id}/approve", data={"version": version, "plan_hash": digest_v2, "csrf": csrf})
    await system.settle()
    work = system.plane.work(work_id)
    assert work["state"] == "done", work  # type: ignore[index]

    detail = system.plane.detail(work_id)
    assert detail is not None
    kinds = [e["kind"] for e in detail["ledger"]]
    for kind in (
        "work.created",
        "consult.asked",
        "consult.answered",
        "plan.ready",
        "message",
        "approval.granted",
        "run.launched",
        "run.finished",
    ):
        assert kind in kinds, kind
    assert kinds.count("run.step.end") == 2
    assert [s["detail"] for s in detail["steps"] if s["event"] == "step.end"] == [
        "echo draining api",
        "echo restarting api",
    ]
    assert system.plane.ledger.verify()["intact"]

    run = detail["runs"][0]["result"]
    assert run["isolation"] == "none" and run["groups"][0]["record_intact"]
    approval_id = detail["approvals"][0]["id"]
    streamed = read_lines(Path(system.launcher.config.runs_dir) / approval_id / "group-1.jsonl")
    assert verify_lines(streamed)["head"] == run["groups"][0]["record_head"]

    # The investigator was refused its one write, and nothing it did reached the launcher.
    record = read_lines(tmp_path / "infra" / ".airlock" / "records" / f"{work_id}.jsonl")
    assert [line["kind"] for line in record].count("tool.refused") == 1

    events = [r.headers["X-Airlock-Event"] for r in system.hooks]
    assert "plan.ready" in events and "plan.revised" in events and events[-1] == "ledger.checkpoint"
    await system.close()


async def test_a_control_plane_talked_into_a_wider_worker_still_cannot_run_it(
    tmp_path: Path, config_dict: dict[str, Any], env: dict[str, str]
) -> None:
    # The launcher holds the authoritative worker list. Here its copy of "ops" may
    # only run `true`, while the control plane's copy would allow the echo steps.
    narrow = [
        {"name": "ops", "modes": ["commands"], "allowed_permissions": ["svc:restart"], "command_allowlist": ["true"]}
    ]
    system = System(tmp_path, config_dict, env, launcher_workers=narrow)
    work_id = await system.alert()
    await system.settle()
    await system.login()
    _, csrf, digest, version = await system.page(work_id)
    await system.web.post(f"/work/{work_id}/approve", data={"version": version, "plan_hash": digest, "csrf": csrf})
    await system.settle()
    work = system.plane.work(work_id)
    assert work["state"] == "refused" and "not on worker ops's command allowlist" in work["note"]  # type: ignore[index]
    assert not (Path(system.launcher.config.runs_dir) / system.plane.detail(work_id)["approvals"][0]["id"]).exists()  # type: ignore[index]
    await system.close()


async def test_github_issue_routes_to_the_code_investigator(
    tmp_path: Path, config_dict: dict[str, Any], env: dict[str, str]
) -> None:
    system = System(tmp_path, config_dict, env)
    body = json.dumps(
        {
            "action": "labeled",
            "label": {"name": "airlock"},
            "issue": {
                "title": "Checkout is slow",
                "body": "p99 4s",
                "html_url": "https://example.invalid/7",
                "number": 7,
            },
            "repository": {"full_name": "acme/shop"},
        }
    ).encode()
    signature = "sha256=" + hmac.new(env["T_GITHUB"].encode(), body, hashlib.sha256).hexdigest()
    response = await system.web.post(
        "/v1/intake/github", content=body, headers={"X-Hub-Signature-256": signature, "X-GitHub-Event": "issues"}
    )
    work_id = response.json()["work_id"]
    await system.settle()
    work = system.plane.work(work_id)
    assert work["investigator"] == "code" and work["state"] == "answered"  # type: ignore[index]
    await system.close()
