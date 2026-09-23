"""Every use of a worker's dedicated identity must match a run that was approved for it.

    python -m airlock.reconcile --runs RUNS_DIR --worker aws-ops --cloudtrail events.json [--identity ARN]
    python -m airlock.reconcile --runs RUNS_DIR --worker k8s-ops --k8s-audit audit.log --user system:serviceaccount:airlock:k8s-ops

The launcher's record says when each worker's container ran and for which
approval. The target keeps its own record of every call the dedicated identity
made. Laid side by side, each call either falls inside a window airlock opened
for that worker, or it does not — and one that does not is the identity being
used outside airlock, which is the thing this whole system exists to rule out.

AWS calls carry the approval in their User-Agent (``AWS_SDK_UA_APP_ID`` is set
to ``airlock-<approval>`` in every worker container), so a CloudTrail event
names the approval it claims; the claim is checked against that approval's own
window. Kubernetes has no such field, so an audit event is matched on the
identity and the time alone.

Reads files only — an exported CloudTrail JSON (``{"Records": [...]}`` or one
event per line) and a Kubernetes audit log (one event per line). Fetching them
is the deployment's job; this has no credentials and needs none. Exit code 1
when anything does not match.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from airlock.runner.recorder import read_lines

_TAG = re.compile(r"airlock-([0-9a-zA-Z_-]+)")


@dataclass(frozen=True)
class Window:
    approval: str
    worker: str
    start: float
    end: float


def windows(runs_dir: Path) -> list[Window]:
    """When each worker's containers ran, from the launcher's own record of every run."""
    found: list[Window] = []
    for record in sorted(runs_dir.glob("*/launcher.jsonl")):
        approval, started = record.parent.name, {}
        for line in read_lines(record):
            data = line.get("data") or {}
            if line.get("kind") == "group.started":
                started[data.get("group")] = (data.get("worker"), float(line["ts"]))
            elif line.get("kind") == "group.finished" and data.get("group") in started:
                worker, start = started.pop(data.get("group"))
                found.append(Window(approval, str(worker), start, float(line["ts"])))
        for worker, start in started.values():  # a group whose end was never recorded: open until now
            found.append(Window(approval, str(worker), start, float("inf")))
    return found


def _when(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _events(path: Path) -> Iterable[dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith("{") and '"Records"' in text[:200]:
        yield from json.loads(text)["Records"]
        return
    for raw in text.splitlines():
        if raw.strip():
            yield json.loads(raw)


def reconcile_cloudtrail(
    path: Path, runs: list[Window], worker: str, *, identity: str = "", grace: float = 120.0
) -> dict[str, Any]:
    by_approval: dict[str, list[Window]] = {}
    for window in runs:
        by_approval.setdefault(window.approval, []).append(window)
    matched, unmatched = 0, []
    for event in _events(path):
        arn = str((event.get("userIdentity") or {}).get("arn") or "")
        if identity and identity not in arn:
            continue
        when, agent = _when(str(event["eventTime"])), str(event.get("userAgent") or "")
        summary = {
            "time": event["eventTime"],
            "action": f"{event.get('eventSource')}:{event.get('eventName')}",
            "user_agent": agent[:200],
        }
        tag = _TAG.search(agent)
        if tag is None:
            unmatched.append(
                {**summary, "why": "no airlock approval in the User-Agent: the identity was used outside airlock"}
            )
            continue
        claimed = [w for w in by_approval.get(tag.group(1), []) if w.worker == worker]
        if not claimed:
            unmatched.append({**summary, "why": f"names approval {tag.group(1)}, which never ran on {worker}"})
        elif not any(w.start - grace <= when <= w.end + grace for w in claimed):
            unmatched.append({**summary, "why": f"names approval {tag.group(1)}, but outside the time it ran"})
        else:
            matched += 1
    return {"source": "cloudtrail", "worker": worker, "matched": matched, "unmatched": unmatched}


def reconcile_k8s(path: Path, runs: list[Window], worker: str, *, user: str, grace: float = 120.0) -> dict[str, Any]:
    mine = [w for w in runs if w.worker == worker]
    matched, unmatched = 0, []
    for event in _events(path):
        if (event.get("user") or {}).get("username") != user or event.get(
            "stage", "ResponseComplete"
        ) != "ResponseComplete":
            continue
        stamp = str(event.get("stageTimestamp") or event.get("requestReceivedTimestamp"))
        when = _when(stamp)
        if any(w.start - grace <= when <= w.end + grace for w in mine):
            matched += 1
            continue
        ref = event.get("objectRef") or {}
        unmatched.append(
            {
                "time": stamp,
                "action": f"{event.get('verb')} {ref.get('resource', '')}/{ref.get('name', '')} in {ref.get('namespace', '-')}",
                "user_agent": str(event.get("userAgent") or "")[:200],
                "why": f"no {worker} run was open at that time: the identity was used outside airlock",
            }
        )
    return {"source": "k8s-audit", "worker": worker, "matched": matched, "unmatched": unmatched}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m airlock.reconcile", description=__doc__.splitlines()[0])
    parser.add_argument("--runs", required=True, type=Path, help="the launcher's runs directory")
    parser.add_argument("--worker", required=True, help="the worker profile whose identity this is")
    parser.add_argument("--cloudtrail", type=Path, help="exported CloudTrail events")
    parser.add_argument("--identity", default="", help="keep only CloudTrail events whose ARN contains this")
    parser.add_argument("--k8s-audit", type=Path, help="a Kubernetes audit log, one event per line")
    parser.add_argument(
        "--user", default="", help="the worker's Kubernetes username, e.g. system:serviceaccount:airlock:k8s-ops"
    )
    parser.add_argument("--grace", type=float, default=120.0, help="seconds of clock skew allowed around a run")
    args = parser.parse_args(argv)
    if bool(args.cloudtrail) == bool(args.k8s_audit):
        parser.error("give exactly one of --cloudtrail or --k8s-audit")
    if args.k8s_audit and not args.user:
        parser.error("--k8s-audit needs --user")
    runs = windows(args.runs)
    if args.cloudtrail:
        report = reconcile_cloudtrail(args.cloudtrail, runs, args.worker, identity=args.identity, grace=args.grace)
    else:
        report = reconcile_k8s(args.k8s_audit, runs, args.worker, user=args.user, grace=args.grace)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if report["unmatched"] else 0


if __name__ == "__main__":
    sys.exit(main())
