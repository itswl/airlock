"""Reconciliation: each use of a dedicated identity must fall inside a run approved for that worker."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from airlock.reconcile import main, reconcile_cloudtrail, reconcile_k8s, windows

T0 = 1_790_000_000.0


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def a_run(runs: Path, approval: str, worker: str, start: float, end: float | None) -> None:
    """The launcher's record of one group, written at the times given."""
    path = runs / approval / "launcher.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [{"seq": 1, "ts": start, "kind": "group.started", "data": {"group": 1, "worker": worker}}]
    if end is not None:
        lines.append(
            {"seq": 2, "ts": end, "kind": "group.finished", "data": {"group": 1, "worker": worker, "status": "done"}}
        )
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))


@pytest.fixture
def runs(tmp_path: Path) -> Path:
    root = tmp_path / "runs"
    a_run(root, "ap1", "aws-ops", T0, T0 + 60)
    a_run(root, "ap2", "k8s-ops", T0 + 1000, T0 + 1100)
    a_run(root, "ap3", "aws-ops", T0 + 5000, None)
    return root


def trail(path: Path, events: list[dict]) -> Path:
    path.write_text(json.dumps({"Records": events}))
    return path


def aws(
    ts: float, agent: str, name: str = "RebootDBInstance", arn: str = "arn:aws:iam::1:user/airlock-aws-ops"
) -> dict:
    return {
        "eventTime": iso(ts),
        "eventSource": "rds.amazonaws.com",
        "eventName": name,
        "userAgent": agent,
        "userIdentity": {"arn": arn},
    }


def test_windows_come_from_the_launchers_own_record(runs: Path) -> None:
    found = {w.approval: (w.worker, w.start, w.end) for w in windows(runs)}
    assert found["ap1"] == ("aws-ops", T0, T0 + 60)
    assert found["ap3"][2] == float("inf"), "a group that never finished stays open"


def test_cloudtrail_calls_must_name_an_approval_that_ran_then(runs: Path, tmp_path: Path) -> None:
    events = [
        aws(T0 + 30, "aws-cli/2.17 md/Botocore app/airlock-ap1"),
        aws(T0 + 30, "aws-cli/2.17 md/Botocore", name="DeleteDBInstance"),
        aws(T0 + 900, "aws-cli/2.17 app/airlock-ap1"),
        aws(T0 + 30, "aws-cli/2.17 app/airlock-ap2"),
        aws(T0 + 30, "console", arn="arn:aws:iam::1:user/somebody-else"),
    ]
    report = reconcile_cloudtrail(
        trail(tmp_path / "ct.json", events), windows(runs), "aws-ops", identity="user/airlock-aws-ops"
    )
    assert report["matched"] == 1
    whys = [u["why"] for u in report["unmatched"]]
    assert (
        whys[0].startswith("no airlock approval")
        and report["unmatched"][0]["action"] == "rds.amazonaws.com:DeleteDBInstance"
    )
    assert "outside the time it ran" in whys[1] and "never ran on aws-ops" in whys[2] and len(whys) == 3


def test_kubernetes_events_are_matched_on_identity_and_time(runs: Path, tmp_path: Path) -> None:
    user = "system:serviceaccount:airlock:k8s-ops"
    lines = [
        {
            "user": {"username": user},
            "stage": "ResponseComplete",
            "stageTimestamp": iso(T0 + 1050),
            "verb": "patch",
            "objectRef": {"resource": "deployments", "name": "api", "namespace": "payments"},
        },
        {"user": {"username": user}, "stage": "RequestReceived", "stageTimestamp": iso(T0 + 3000), "verb": "delete"},
        {
            "user": {"username": user},
            "stage": "ResponseComplete",
            "stageTimestamp": iso(T0 + 3000),
            "verb": "delete",
            "objectRef": {"resource": "pods", "name": "api-1", "namespace": "payments"},
        },
        {
            "user": {"username": "someone"},
            "stage": "ResponseComplete",
            "stageTimestamp": iso(T0 + 3000),
            "verb": "delete",
        },
    ]
    audit = tmp_path / "audit.log"
    audit.write_text("\n".join(json.dumps(line) for line in lines))
    report = reconcile_k8s(audit, windows(runs), "k8s-ops", user=user)
    assert report["matched"] == 1 and len(report["unmatched"]) == 1
    assert report["unmatched"][0]["action"] == "delete pods/api-1 in payments"


def test_the_command_line_exit_code_is_the_alarm(
    runs: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    clean = trail(tmp_path / "clean.json", [aws(T0 + 10, "app/airlock-ap1")])
    assert main(["--runs", str(runs), "--worker", "aws-ops", "--cloudtrail", str(clean)]) == 0
    assert json.loads(capsys.readouterr().out)["matched"] == 1
    dirty = trail(tmp_path / "dirty.json", [aws(T0 + 10, "boto3/1.35")])
    assert main(["--runs", str(runs), "--worker", "aws-ops", "--cloudtrail", str(dirty)]) == 1
    assert len(json.loads(capsys.readouterr().out)["unmatched"]) == 1
    with pytest.raises(SystemExit):
        main(["--runs", str(runs), "--worker", "k8s-ops", "--k8s-audit", str(dirty)])
