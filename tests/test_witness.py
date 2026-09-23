"""The ledger witness: it keeps what it is sent, and it catches a ledger rebuilt to look intact."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from airlock.config import load_control
from airlock.control.service import ControlPlane
from airlock.crypto import sign
from airlock.db import Database
from airlock.ledger import SEED, Ledger, entry_hash
from airlock.witness import Witness, check, create_witness_app, main
from tests.conftest import Router


class Clock:
    def __init__(self) -> None:
        self.now = 1_700_000_000.0

    def __call__(self) -> float:
        return self.now


def delivery(
    secret: str, delivery_id: int, payload: dict[str, Any], event: str = "ledger.checkpoint"
) -> tuple[bytes, dict[str, str]]:
    body = json.dumps({"id": delivery_id, "event": event, "at": 1.0, "payload": payload}).encode()
    return body, sign(secret, body)


def test_it_keeps_checkpoints_once_and_ignores_the_rest(tmp_path: Path) -> None:
    witness = Witness(tmp_path / "heads.jsonl", "s3cret")
    assert witness.receive(*delivery("s3cret", 1, {"seq": 3, "head": "a" * 64}))[1]["status"] == "kept"
    assert witness.receive(*delivery("s3cret", 1, {"seq": 3, "head": "a" * 64}))[1]["status"] == "already kept"
    assert witness.receive(*delivery("s3cret", 2, {"work_id": "w"}, event="plan.ready"))[0] == 202
    assert witness.receive(*delivery("wrong", 3, {"seq": 4, "head": "b" * 64}))[0] == 401
    assert witness.receive(*delivery("s3cret", 4, {"seq": "x", "head": 1}))[0] == 400
    again = Witness(tmp_path / "heads.jsonl", "s3cret")
    assert again.receive(*delivery("s3cret", 1, {"seq": 3, "head": "a" * 64}))[1]["status"] == "already kept"
    with pytest.raises(ValueError):
        Witness(tmp_path / "x.jsonl", "")


def ledger_with(path: Path, n: int) -> Ledger:
    ledger = Ledger(Database(path))
    for i in range(n):
        ledger.append("thing", work_id="w", data={"n": i}, now=1_700_000_000.0 + i)
    return ledger


def keep(witness: Witness, ledger: Ledger, delivery_id: int) -> None:
    last = ledger.last()
    assert witness.receive(*delivery("s", delivery_id, {"seq": last["seq"], "head": last["hash"]}))[0] == 200


def rebuild_from(db: Database, seq: int, data: dict[str, Any]) -> None:
    """What somebody with write access does: change an entry and recompute every hash after it."""
    rows = db.all("SELECT * FROM ledger ORDER BY seq")
    previous = SEED
    for row in rows:
        if row["seq"] == seq:
            row["data"] = json.dumps(data, sort_keys=True)
        row["prev"] = previous
        row["hash"] = entry_hash(row)
        db.execute(
            "UPDATE ledger SET data = ?, prev = ?, hash = ? WHERE seq = ?",
            [row["data"], row["prev"], row["hash"], row["seq"]],
        )
        previous = row["hash"]


def test_a_rebuilt_ledger_verifies_on_its_own_but_not_against_the_witness(tmp_path: Path) -> None:
    db_path = tmp_path / "control.db"
    ledger = ledger_with(db_path, 5)
    witness = Witness(tmp_path / "heads.jsonl", "s")
    keep(witness, ledger, 1)
    for i in range(3):
        ledger.append("more", data={"n": i})
    keep(witness, ledger, 2)
    assert check(db_path, tmp_path / "heads.jsonl") == {
        "ledger_intact": True,
        "ledger_entries": 8,
        "witness_record_intact": True,
        "heads_checked": 2,
        "mismatch": None,
        "ok": True,
    }

    rebuild_from(ledger.db, 2, {"n": "rewritten"})
    assert ledger.verify()["intact"], "the rewrite is invisible to the chain alone"
    report = check(db_path, tmp_path / "heads.jsonl")
    assert not report["ok"] and report["mismatch"].startswith("seq 5 is not what was witnessed")


def test_a_truncated_ledger_or_a_tampered_witness_is_named(tmp_path: Path) -> None:
    db_path = tmp_path / "control.db"
    ledger = ledger_with(db_path, 4)
    witness = Witness(tmp_path / "heads.jsonl", "s")
    keep(witness, ledger, 1)
    ledger.db.execute("DELETE FROM ledger WHERE seq = 4")
    assert "no longer has it" in check(db_path, tmp_path / "heads.jsonl")["mismatch"]

    lines = (tmp_path / "heads.jsonl").read_text().splitlines()
    doctored = json.loads(lines[0])
    doctored["data"]["seq"] = 1
    (tmp_path / "heads.jsonl").write_text(json.dumps(doctored) + "\n")
    assert "witness's own record breaks" in check(db_path, tmp_path / "heads.jsonl")["mismatch"]


def test_the_command_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_path = tmp_path / "control.db"
    ledger = ledger_with(db_path, 2)
    keep(Witness(tmp_path / "heads.jsonl", "s"), ledger, 1)
    assert main(["verify", "--db", str(db_path), "--store", str(tmp_path / "heads.jsonl")]) == 0
    assert json.loads(capsys.readouterr().out)["heads_checked"] == 1
    rebuild_from(ledger.db, 1, {"n": "x"})
    assert main(["verify", "--db", str(db_path), "--store", str(tmp_path / "heads.jsonl")]) == 1


@pytest.mark.anyio
async def test_the_control_plane_feeds_the_witness_through_its_outlet(
    tmp_path: Path, config_dict: dict[str, Any], env: dict[str, str]
) -> None:
    config = dict(config_dict)
    config["control"] = {**config_dict["control"], "checkpoint_seconds": 600}
    config["subscriptions"] = [
        {"name": "witness", "url": "http://witness/", "secret_env": "T_HOOKS", "events": ["ledger.checkpoint"]}
    ]
    clock = Clock()
    witness = Witness(tmp_path / "heads.jsonl", env["T_HOOKS"], clock=clock)
    router = Router()
    router.mount("witness", create_witness_app(witness))
    router.handle("infra", lambda request: httpx.Response(202))
    plane = ControlPlane(load_control(config, env), client=httpx.AsyncClient(transport=router), clock=clock)

    plane.manual_signal("t", "b")
    await plane.tick()
    assert len(witness.seen) == 1, "the first tick hands over the head at once"
    await plane.tick()
    assert len(witness.seen) == 1, "nothing new within the interval"
    plane.manual_signal("t2", "b")
    clock.now += 601
    await plane.tick()
    assert len(witness.seen) == 2
    witness_heads = [json.loads(line)["data"] for line in (tmp_path / "heads.jsonl").read_text().splitlines()]
    assert witness_heads[-1]["head"] == plane.ledger.at(witness_heads[-1]["seq"])["hash"]  # type: ignore[index]
    assert check(Path(config["control"]["db_path"]), tmp_path / "heads.jsonl")["ok"]
