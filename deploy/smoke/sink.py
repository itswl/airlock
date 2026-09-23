"""Stands in for a custom bot's webhook, for scripts/extras_smoke.py only: records every card and answers like the platform."""

from __future__ import annotations

from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request

RECORDS = Path("/records")
app = FastAPI()


@app.post("/{path}")
async def take(path: str, request: Request) -> dict:
    RECORDS.mkdir(parents=True, exist_ok=True)
    with (RECORDS / f"{path}.jsonl").open("a", encoding="utf-8") as handle:
        handle.write((await request.body()).decode("utf-8", "replace").replace("\n", " ") + "\n")
    return {"code": 0, "msg": "success"}


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000, log_level="warning")  # noqa: S104 — a container on a smoke network
