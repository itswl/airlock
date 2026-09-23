from __future__ import annotations

import json
from pathlib import Path

from airlock.db import Database
from airlock.ledger import Ledger
from airlock.runner.recorder import Recorder, read_lines, verify_lines


def test_ledger_chain_verifies_and_names_the_first_broken_entry(tmp_path: Path) -> None:
    db = Database(tmp_path / "l.db")
    ledger = Ledger(db)
    for n in range(5):
        ledger.append("thing", work_id="w", data={"n": n})
    check = ledger.verify()
    assert check["intact"] and check["checked"] == 5 and check["head"] == ledger.head()

    db.execute("UPDATE ledger SET data = ? WHERE seq = 3", [json.dumps({"n": 99})])
    check = ledger.verify()
    assert not check["intact"] and check["broken_at"] == 3


def test_ledger_detects_a_deleted_entry(tmp_path: Path) -> None:
    db = Database(tmp_path / "l.db")
    ledger = Ledger(db)
    for n in range(4):
        ledger.append("thing", data={"n": n})
    db.execute("DELETE FROM ledger WHERE seq = 2")
    assert ledger.verify()["broken_at"] == 3


def test_ledger_entries_by_work_item(tmp_path: Path) -> None:
    ledger = Ledger(Database(tmp_path / "l.db"))
    ledger.append("a", work_id="one")
    ledger.append("b", work_id="two")
    ledger.append("c", work_id="one")
    assert [e["kind"] for e in ledger.entries(work_id="one")] == ["a", "c"]


def test_recorder_resumes_its_chain_and_tampering_shows(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    first = Recorder(path)
    first.write("start", x=1)
    Recorder(path).write("end", x=2)
    lines = read_lines(path)
    assert [line["seq"] for line in lines] == [1, 2]
    assert verify_lines(lines)["intact"]

    lines[0]["data"]["x"] = 5
    assert verify_lines(lines) == {"intact": False, "checked": 0, "broken_at": 1, "head": "0" * 64}


def test_recorder_sink_streams_the_same_lines(tmp_path: Path) -> None:
    streamed: list[str] = []
    recorder = Recorder(tmp_path / "r.jsonl", sink=streamed.append)
    recorder.write("a")
    recorder.write("b", y=[1, 2])
    parsed = [json.loads(s) for s in streamed]
    assert parsed == read_lines(tmp_path / "r.jsonl")
    assert verify_lines(parsed)["head"] == recorder.head
