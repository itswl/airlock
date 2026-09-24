"""Did the investigators help? A report over a window, from what the ledger and the tables already hold.

Two kinds of evidence, kept apart:

* what you **said**: a rating per work item, useful or useless, given on the
  console or by a reply under its card;
* what you **did**: the outcome, which needs no click. A plan approved and run
  to done is the strongest evidence a report helped. Other outcomes are a
  rejected plan, an approval left to lapse, a report you asked about, and a
  report nothing ever happened to.

hookstack learned the second half the hard way. Nobody pressed the rating
buttons on its cards, so a report built only on ratings would have measured
nothing for months.

A run the sandbox rule approved is kept apart from the ones you approved.
Nobody chose it, so its outcome says only that it ran; whether the diff was
worth it is your rating.

Nothing here decides anything. The report reads; approval and budgets never
look at it.
"""

from __future__ import annotations

import json
import statistics
from collections import Counter
from typing import Any

from airlock.db import Database

OUTCOMES = {
    "acted_on": "已执行成功",
    "acted_on_failed": "执行未成功",
    "ran_in_sandbox": "规则批准，沙箱里跑完",
    "sandbox_failed": "规则批准，沙箱里没跑成",
    "rejected": "方案被驳回",
    "approval_lapsed": "批准过期或撤回",
    "awaiting_you": "等你批准",
    "in_progress": "进行中",
    "investigation_failed": "调查失败",
    "discussed": "你追问过",
    "no_response": "没有回应",
}
_OPEN = ("queued", "investigating", "approved", "running")
_ANSWERS = ("investigation.answered", "plan.ready", "plan.revised", "plan.invalid")


def by_rule(approver: str) -> bool:
    return approver.startswith("policy:")


def outcome(state: str, runs: list[tuple[str, str]], approvals: list[str], operator_messages: int) -> str:
    """``runs`` is (status, approver) for each run: one the sandbox rule approved is not something you did."""
    yours = [status for status, approver in runs if not by_rule(approver)]
    ruled = [status for status, approver in runs if by_rule(approver)]
    if "done" in yours:
        return "acted_on"
    if yours:
        return "acted_on_failed"
    if "done" in ruled:
        return "ran_in_sandbox"
    if ruled:
        return "sandbox_failed"
    if state == "rejected":
        return "rejected"
    if any(a in ("expired", "revoked") for a in approvals):
        return "approval_lapsed"
    if state in _OPEN:
        return "in_progress"
    if state == "plan_ready":
        return "awaiting_you"
    if state in ("error", "plan_invalid"):
        return "investigation_failed"
    return "discussed" if operator_messages else "no_response"


def _median_minutes(seconds: list[float]) -> float | None:
    return round(statistics.median(seconds) / 60, 1) if seconds else None


def build_report(db: Database, operator: str, *, days: int, now: float) -> dict[str, Any]:
    since = now - days * 86400
    items = db.all("SELECT * FROM work_items WHERE created_at >= ? ORDER BY created_at DESC", [since])
    ids = [i["id"] for i in items]
    marks = ",".join("?" * len(ids)) or "''"

    def grouped(sql: str) -> dict[str, list[dict[str, Any]]]:
        out: dict[str, list[dict[str, Any]]] = {}
        for row in db.all(sql.format(marks=marks), ids):
            out.setdefault(row["work_id"], []).append(row)
        return out

    plans = grouped("SELECT work_id, version, errors FROM plans WHERE work_id IN ({marks}) ORDER BY version")
    approvals = grouped("SELECT work_id, status, version, at, approver FROM approvals WHERE work_id IN ({marks})")
    runs = grouped(
        "SELECT r.work_id, r.status, a.approver FROM runs r JOIN approvals a ON a.id = r.approval_id "
        "WHERE r.work_id IN ({marks})"
    )
    ratings = {r["work_id"]: r for r in db.all(f"SELECT * FROM ratings WHERE work_id IN ({marks})", ids)}  # noqa: S608
    said = Counter(
        r["work_id"]
        for r in db.all(f"SELECT work_id FROM messages WHERE work_id IN ({marks}) AND author = ?", [*ids, operator])  # noqa: S608
    )
    ledger = grouped(
        "SELECT work_id, kind, ts, data FROM ledger WHERE work_id IN ({marks}) "
        "AND kind IN ('investigation.dispatched', 'investigation.answered', 'plan.ready', 'plan.revised', "
        "'plan.invalid', 'investigation.failed', 'investigation.timed_out') ORDER BY seq"
    )
    cost = 0.0
    tokens: Counter[str] = Counter()
    refusals = 0
    rounds = 0
    durations: list[float] = []
    waits: list[float] = []
    failed_rounds = 0
    rows = []
    for item in items:
        work_id = item["id"]
        dispatched: float | None = None
        ready_at: dict[int, float] = {}
        for entry in ledger.get(work_id, []):
            data = json.loads(entry["data"] or "{}")
            if entry["kind"] == "investigation.dispatched":
                dispatched = entry["ts"]
                continue
            if entry["kind"] in ("investigation.failed", "investigation.timed_out"):
                failed_rounds += 1
                dispatched = None
                continue
            if entry["kind"] in _ANSWERS:
                rounds += 1
                cost += float(data.get("cost_usd") or 0)
                refusals += int(data.get("refusals") or 0)
                tokens.update({k: int(v) for k, v in (data.get("usage") or {}).items() if isinstance(v, int | float)})
                if dispatched is not None:
                    durations.append(entry["ts"] - dispatched)
                    dispatched = None
                if entry["kind"] in ("plan.ready", "plan.revised") and data.get("version"):
                    ready_at.setdefault(int(data["version"]), entry["ts"])
        for approval in approvals.get(work_id, []):
            if approval["version"] in ready_at and not by_rule(approval["approver"]):
                waits.append(approval["at"] - ready_at[approval["version"]])
        versions = plans.get(work_id, [])
        rating = ratings.get(work_id)
        result = outcome(
            item["state"],
            [(r["status"], r["approver"]) for r in runs.get(work_id, [])],
            [a["status"] for a in approvals.get(work_id, [])],
            said.get(work_id, 0),
        )
        rows.append(
            {
                "id": work_id,
                "created_at": item["created_at"],
                "source": item["source"],
                "investigator": item["investigator"],
                "title": item["title"],
                "state": item["state"],
                "versions": len(versions),
                "first_plan_valid": bool(versions) and json.loads(versions[0]["errors"] or "[]") == [],
                "outcome": result,
                "rating": rating["rating"] if rating else None,
                "rating_note": rating["note"] if rating else "",
            }
        )
    with_plan = [r for r in rows if r["versions"]]
    return {
        "window": {"days": days, "since": since, "until": now},
        "work_items": len(rows),
        "by_source": dict(Counter(r["source"] for r in rows)),
        "by_investigator": dict(Counter(r["investigator"] for r in rows)),
        "outcomes": {k: sum(1 for r in rows if r["outcome"] == k) for k in OUTCOMES},
        "ratings": {
            "useful": sum(1 for r in rows if r["rating"] == "useful"),
            "useless": sum(1 for r in rows if r["rating"] == "useless"),
            "unrated": sum(1 for r in rows if r["rating"] is None),
        },
        "plans": {
            "items_with_plan": len(with_plan),
            "first_plan_valid": sum(1 for r in with_plan if r["first_plan_valid"]),
            "average_versions": round(sum(r["versions"] for r in with_plan) / len(with_plan), 2) if with_plan else None,
        },
        "approvals": {
            "median_wait_minutes": _median_minutes(waits),
            "count": len(waits),
            "by_rule": sum(1 for rows in approvals.values() for a in rows if by_rule(a["approver"])),
        },
        "runs": dict(Counter(r["status"] for rs in runs.values() for r in rs)),
        "investigations": {
            "rounds": rounds,
            "failed_rounds": failed_rounds,
            "median_minutes": _median_minutes(durations),
            "cost_usd": round(cost, 4),
            "tokens": dict(tokens),
            "refusals": refusals,
        },
        "items": rows,
    }
