"""A ledger witness: keep every ledger head the control plane hands out, somewhere it cannot rewrite.

    python -m airlock.witness serve --store heads.jsonl --secret-env AIRLOCK_SUB_WITNESS_SECRET
    python -m airlock.witness verify --db control.db --store heads.jsonl

The ledger's hash chain shows an edit made by somebody who did not recompute
the chain. It cannot show one made by somebody who did: rewrite an entry, redo
every hash after it, and the chain verifies again. What catches that is a copy
of an old head kept elsewhere. So the control plane publishes ``ledger.checkpoint``
(its latest seq and hash) after every run and every ``checkpoint_seconds``, and
this process — run on another machine, under another account — keeps each one.

``serve`` is a subscriber of the pipe's outlet: it checks the outbox signature,
keeps checkpoints and ignores every other event, and keeps each delivery once
however often it is retried. Its own store is a chained record, so it can be
checked the same way.

``verify`` reads the control plane's ledger and every witnessed head: the chain
must be intact, and at every witnessed seq the ledger must still hold the hash
the witness was given. The first difference is named; the exit code is 1.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from airlock import __version__
from airlock.crypto import SignatureError, verify
from airlock.db import Database
from airlock.ledger import Ledger
from airlock.runner.recorder import Recorder, read_lines, verify_lines


class Witness:
    def __init__(self, store: Path, secret: str, *, clock: Callable[[], float] = time.time) -> None:
        if not secret:
            raise ValueError("a witness needs the subscription secret to check what it is sent")
        self.store = store
        self.secret = secret
        self.clock = clock
        self.recorder = Recorder(store)
        self.seen = {line["data"].get("delivery") for line in read_lines(store)}

    def receive(self, body: bytes, headers: Any) -> tuple[int, dict[str, Any]]:
        try:
            verify(self.secret, body, headers, now=self.clock())
        except SignatureError as exc:
            return 401, {"reason": str(exc)}
        try:
            envelope = json.loads(body)
        except ValueError:
            return 400, {"reason": "the body is not JSON"}
        if envelope.get("event") != "ledger.checkpoint":
            return 202, {"status": "ignored"}
        delivery, payload = envelope.get("id"), envelope.get("payload") or {}
        if delivery in self.seen:
            return 200, {"status": "already kept"}
        if not isinstance(payload.get("seq"), int) or not isinstance(payload.get("head"), str):
            return 400, {"reason": "a checkpoint names a seq and a head"}
        self.recorder.write(
            "checkpoint", delivery=delivery, seq=payload["seq"], head=payload["head"], sent_at=envelope.get("at")
        )
        self.seen.add(delivery)
        return 200, {"status": "kept", "seq": payload["seq"]}


def create_witness_app(witness: Witness) -> FastAPI:
    app = FastAPI(title="airlock ledger witness", version=__version__, docs_url=None, redoc_url=None)

    @app.post("/")
    async def receive(request: Request) -> JSONResponse:
        status, body = witness.receive(await request.body(), request.headers)
        if status == 401:
            raise HTTPException(401, body["reason"])
        return JSONResponse(body, status_code=status)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "kept": len(witness.seen)}

    return app


def check(db_path: Path, store: Path) -> dict[str, Any]:
    """The control plane's ledger against every head the witness kept."""
    ledger = Ledger(Database(db_path))
    chain = ledger.verify()
    kept = read_lines(store)
    own = verify_lines(kept)
    report: dict[str, Any] = {
        "ledger_intact": chain["intact"],
        "ledger_entries": chain["checked"],
        "witness_record_intact": own["intact"],
        "heads_checked": 0,
        "mismatch": None,
    }
    if not chain["intact"]:
        report["mismatch"] = f"the ledger's own chain breaks at seq {chain['broken_at']}"
    elif not own["intact"]:
        report["mismatch"] = f"the witness's own record breaks at line {own['broken_at']}"
    else:
        for line in kept:
            seq, head = line["data"]["seq"], line["data"]["head"]
            entry = ledger.at(seq)
            report["heads_checked"] += 1
            if entry is None:
                report["mismatch"] = f"seq {seq} was witnessed but the ledger no longer has it"
                break
            if entry["hash"] != head:
                report["mismatch"] = f"seq {seq} is not what was witnessed: the ledger was rewritten at or before it"
                break
    report["ok"] = report["mismatch"] is None
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m airlock.witness", description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="keep the checkpoints the control plane sends")
    serve.add_argument("--store", required=True, type=Path)
    serve.add_argument("--secret-env", required=True, help="environment variable holding the subscription secret")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8095)
    audit = commands.add_parser("verify", help="check a control plane ledger against the kept heads")
    audit.add_argument("--db", required=True, type=Path)
    audit.add_argument("--store", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == "verify":
        report = check(args.db, args.store)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0 if report["ok"] else 1
    import uvicorn

    witness = Witness(args.store, os.environ.get(args.secret_env, ""))
    uvicorn.run(create_witness_app(witness), host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
