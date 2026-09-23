"""An investigator node's ceiling: priced from tokens, rolling, and refused where it can be seen."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from airlock.runner.budget import Budget, rates_from
from airlock.runner.engine import StubEngine, StubTurn
from airlock.runner.investigator import InvestigatorNode, load_node


class Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


USAGE = {
    "input_tokens": 1000,
    "output_tokens": 500,
    "cache_read_input_tokens": 100_000,
    "cache_creation_input_tokens": 0,
}


def test_a_turn_is_priced_from_its_tokens_when_rates_are_declared(tmp_path: Path) -> None:
    rates = rates_from(
        {"AIRLOCK_PRICE_IN_PER_1M": "0.5", "AIRLOCK_PRICE_OUT_PER_1M": "2", "AIRLOCK_PRICE_CACHE_READ_PER_1M": "0.05"}
    )
    assert rates.price(USAGE) == pytest.approx(0.0005 + 0.001 + 0.005)
    budget = Budget(tmp_path / "spend.jsonl", limit_usd=1.0, rates=rates)
    assert budget.charge("x", cli_cost=0.9, usage=USAGE) == (pytest.approx(0.0065), "rates")  # not the CLI's 0.9
    assert Budget(tmp_path / "other.jsonl", limit_usd=1.0).charge("x", 0.9, USAGE) == (0.9, "cli")


def test_the_window_rolls_and_the_refusal_says_how_to_go_on(tmp_path: Path) -> None:
    clock = Clock()
    budget = Budget(tmp_path / "spend.jsonl", limit_usd=0.5, window_hours=24, clock=clock)
    budget.charge("a", 0.3, None)
    assert budget.refusal() is None
    budget.charge("b", 0.3, None)
    refusal = budget.refusal()
    assert refusal is not None and "$0.60" in refusal and "$0.50" in refusal and "新会话重查" in refusal
    clock.now += 25 * 3600
    assert budget.refusal() is None and budget.spent() == 0
    assert Budget(tmp_path / "none.jsonl", limit_usd=None).refusal() is None


@pytest.mark.anyio
async def test_a_node_over_its_ceiling_refuses_and_says_so_to_the_work_item(tmp_path: Path) -> None:
    env = {
        "AIRLOCK_PROFILE": "infra",
        "AIRLOCK_SECRET": "s" * 32,
        "AIRLOCK_CONTROL_URL": "http://control",
        "AIRLOCK_WORKDIR": str(tmp_path / "work"),
        "AIRLOCK_STATE_DIR": str(tmp_path / "state"),
        "AIRLOCK_BUDGET_USD": "0.1",
    }
    (tmp_path / "work").mkdir()
    posted: list[tuple[str, dict[str, Any]]] = []

    def control(request: httpx.Request) -> httpx.Response:
        import json

        posted.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={})

    ran: list[str] = []

    def turn(request: Any) -> StubTurn:
        ran.append(request.prompt[:10])
        return StubTurn(text="Findings: fine.")

    node = InvestigatorNode(
        load_node(env), StubEngine(turn), client=httpx.AsyncClient(transport=httpx.MockTransport(control))
    )
    node.budget.charge("earlier", 0.2, None)
    await node._investigate({"work_id": "w1", "title": "t", "body": "b"})
    assert ran == [] and posted[-1][0] == "/v1/investigations/error" and "budget" in posted[-1][1]["error"]
    status, answer = await node.answer({"work_id": "w1", "question": "q"})
    assert status == 200 and answer["answer"].startswith("budget:") and ran == []
