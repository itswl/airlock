"""python -m airlock.extras.watch --config watch.yaml [--once] [--force] [--dry-run]

Runs a round on every multiple of ``schedule.every_minutes`` on the wall clock
(:00 :20 :40), inside the working hours, and logs one line per tick. That line
is how you tell a clock that stopped from a quiet afternoon. ``--once`` runs
one round now and exits. ``--force`` runs it outside the hours too.
``--dry-run`` scans and judges but delivers nothing and moves no cursor, so you
can read what a round would have said.
``--report DAYS`` reads the record back: rounds that ran the model and rounds
that did not, tasks and notes raised, signals dropped, deliveries failed, cost.

Each round is kept twice. ``rounds.jsonl`` is a chained record: scan size,
offered subjects, the judge's signals and what was dropped, each delivery and
its answer. ``rounds/<time>.md`` is the case file: the digest the model read
and the answer it gave. ``status.json`` is overwritten every tick.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import logging
import math
import os
import sys
import time
from pathlib import Path
from typing import Any

from airlock.crypto import sha256_hex
from airlock.extras.watch.config import WatchConfig, WatchConfigError, load_watch
from airlock.extras.watch.deliver import deliver
from airlock.extras.watch.jira import http_fetch
from airlock.extras.watch.judge import default_engine, judge, summary
from airlock.extras.watch.mcp import McpClient
from airlock.extras.watch.scan import Scanner, in_window, write_atomically
from airlock.runner.recorder import Recorder, read_lines

logger = logging.getLogger("airlock.watch")


def status(config: WatchConfig, **fields: Any) -> None:
    """What the self-check reads: when this ticked, when a round last ran, and how it went."""
    path = config.state_dir / "status.json"
    try:
        previous = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, ValueError):
        previous = {}
    schedule = dataclasses.asdict(config.schedule)
    write_atomically(path, {**previous, **fields, "schedule": schedule, "name": config.name})


def run_round(
    config: WatchConfig,
    scanner: Scanner,
    record: Recorder,
    *,
    engine_factory: Any = None,
    force: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    tick = time.time()
    scan = scanner.run(force=force, persist=not dry_run)
    if scan is None:
        outcome = "quiet" if force or in_window(config.schedule, tick) else "outside"
        if not dry_run:
            status(config, tick_at=tick, outcome=outcome)
            if outcome == "quiet":
                record.write("round.quiet")  # counted by --report: a round that cost nothing
        return {"outcome": outcome}
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(scan.at))
    judgement = asyncio.run(
        judge(config, scan, engine_factory or default_engine(config), record=None if dry_run else record.write)
    )
    case = config.state_dir / "rounds" / f"{stamp}.md"
    if not dry_run:
        case.parent.mkdir(parents=True, exist_ok=True)
        case.write_text(f"{scan.digest}\n\n---\n\n{judgement.text}\n", encoding="utf-8")
    if not dry_run and not judgement.error:
        scanner.commit(scan)
    deliveries = [] if dry_run or judgement.error else deliver(config, judgement.signals, scan.at)
    result = {
        "outcome": "error" if judgement.error else ("dry-run" if dry_run else "fired"),
        "digest_sha256": sha256_hex(scan.digest.encode()),
        "digest_bytes": len(scan.digest.encode()),
        "offered": sorted(scan.offered),
        "judge": summary(judgement),
        "deliveries": [dataclasses.asdict(d) for d in deliveries],
    }
    if dry_run:
        result["digest"] = scan.digest
        result["signals"] = [dataclasses.asdict(s) for s in judgement.signals]
        return result
    record.write("round", case=str(case), **result)
    failed = [d for d in deliveries if not d.ok]
    status(
        config,
        tick_at=tick,
        round_at=scan.at,
        outcome=result["outcome"],
        signals=len(judgement.signals),
        failed_deliveries=len(failed),
        error=judgement.error or (failed[0].reason if failed else None),
    )
    return result


def report(path: Path, days: int, *, now: float | None = None) -> dict[str, Any]:
    """Rounds over the last ``days``: how many ran the model, what they raised, what was dropped, what failed."""
    since = (time.time() if now is None else now) - days * 86400
    lines = [line for line in read_lines(path) if float(line.get("ts") or 0) >= since]
    rounds = [line["data"] for line in lines if line.get("kind") == "round"]
    deliveries = [d for r in rounds for d in r.get("deliveries") or []]
    # A task is delivered twice (to the intake, then as its card): count it once, at the intake.
    signals = [d for d in deliveries if d.get("door") == "tasks" or d.get("kind") == "note"]
    return {
        "days": days,
        "quiet_rounds": sum(1 for line in lines if line.get("kind") == "round.quiet"),
        "judged_rounds": len(rounds),
        "failed_rounds": sum(1 for r in rounds if r.get("outcome") == "error"),
        "tasks": sum(1 for d in signals if d.get("kind") == "task"),
        "notes": sum(1 for d in signals if d.get("kind") == "note"),
        "high": sum(1 for d in signals if d.get("level") == "high"),
        "dropped_signals": sum(len((r.get("judge") or {}).get("dropped") or []) for r in rounds),
        "failed_deliveries": sum(1 for d in deliveries if not d.get("ok")),
        "cost_usd": round(sum(float((r.get("judge") or {}).get("cost_usd") or 0) for r in rounds), 4),
        "average_digest_bytes": round(sum(r.get("digest_bytes") or 0 for r in rounds) / len(rounds))
        if rounds
        else None,
    }


def seconds_to_next(every_minutes: int, now: float) -> float:
    """Until the next multiple of ``every_minutes`` since local midnight, so restarts do not shift the grid."""
    local = time.localtime(now)
    into_day = local.tm_hour * 3600 + local.tm_min * 60 + local.tm_sec + (now % 1)
    step = every_minutes * 60
    return math.floor(into_day / step + 1) * step - into_day


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m airlock.extras.watch", description=__doc__.splitlines()[0])
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--once", action="store_true", help="one round now, then exit")
    parser.add_argument("--force", action="store_true", help="ignore the working hours")
    parser.add_argument("--dry-run", action="store_true", help="scan and judge; deliver nothing, move no cursor")
    parser.add_argument("--report", type=int, metavar="DAYS", help="what the last DAYS of rounds did, from the record")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        config = load_watch(args.config)
    except (WatchConfigError, OSError) as exc:
        print(f"watch: {exc}", file=sys.stderr)
        return 2
    if config.schedule.tz:
        os.environ["TZ"] = config.schedule.tz
        time.tzset()
    if args.report:
        print(json.dumps(report(config.state_dir / "rounds.jsonl", args.report), ensure_ascii=False, indent=2))
        return 0
    config.state_dir.mkdir(parents=True, exist_ok=True)
    chat = (
        McpClient(
            config.chat.url,
            token=config.chat.token,
            prefix=config.chat.tool_prefix,
            timeout=config.chat.timeout_seconds,
        )
        if config.chat
        else None
    )
    jira = http_fetch(config.jira) if config.jira else None
    scanner = Scanner(config, chat=chat, jira=jira)
    record = Recorder(config.state_dir / "rounds.jsonl")
    if args.once or args.dry_run:
        result = run_round(config, scanner, record, force=args.force, dry_run=args.dry_run)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["outcome"] != "error" else 1
    # Said at once, not at the first tick: a self-check reading status.json between a start
    # and the first tick would otherwise find nothing and take the watcher for dead.
    status(config, tick_at=time.time(), outcome="started")
    logger.info(
        "watch up: every %sm, window %s, days %s, tz %s",
        config.schedule.every_minutes,
        config.schedule.window,
        config.schedule.days,
        config.schedule.tz or "system",
    )
    while True:
        time.sleep(seconds_to_next(config.schedule.every_minutes, time.time()))
        try:
            result = run_round(config, scanner, record)
        except Exception:  # noqa: BLE001 — one broken round is logged and the clock keeps going
            logger.exception("round failed")
            status(config, tick_at=time.time(), outcome="error", error="the round raised; see the log")
            continue
        logger.info(
            "tick: %s%s",
            result["outcome"],
            f", {result['judge']['signals']} signals" if "judge" in result else "",
        )


if __name__ == "__main__":
    sys.exit(main())
