"""The launcher's HTTP surface: two signed doors and a health check. python -m airlock.launcher

``POST /launch`` and ``POST /cancel`` accept only requests signed with the
launcher's secret, which the control plane holds and nothing else does. There is
no door for an investigator, a worker or a browser: the launcher has one caller.
Keep it on a network only the control plane can reach.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from airlock import __version__
from airlock.config import load_launcher
from airlock.crypto import SignatureError, verify
from airlock.launcher.runtime import DockerRuntime, LocalRuntime
from airlock.launcher.service import Launcher

logger = logging.getLogger("airlock.launcher.app")


def create_launcher_app(launcher: Launcher, *, run_loop: bool = True, tick_seconds: float = 10.0) -> FastAPI:
    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await launcher.recover()
        task = asyncio.create_task(_loop(launcher, tick_seconds)) if run_loop else None
        try:
            yield
        finally:
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(title="airlock launcher", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.launcher = launcher

    async def signed(request: Request) -> dict[str, Any]:
        body = await request.body()
        try:
            verify(launcher.config.secret, body, request.headers, now=launcher.clock())
        except SignatureError as exc:
            raise HTTPException(401, str(exc)) from exc
        try:
            data = json.loads(body)
        except ValueError as exc:
            raise HTTPException(400, "the body is not JSON") from exc
        if not isinstance(data, dict):
            raise HTTPException(400, "the body must be a JSON object")
        return data

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {
            "ok": True,
            "version": __version__,
            "isolation": launcher.runtime.isolation,
            "running": sorted(launcher.tasks),
            "workers": sorted(launcher.config.workers),
        }

    @app.post("/launch")
    async def launch(request: Request) -> JSONResponse:
        outcome = launcher.accept(await signed(request))
        return JSONResponse(outcome.body, status_code=outcome.status)

    @app.post("/cancel")
    async def cancel(request: Request) -> JSONResponse:
        payload = await signed(request)
        outcome = await launcher.cancel(str(payload.get("approval_id") or ""))
        return JSONResponse(outcome.body, status_code=outcome.status)

    return app


async def _loop(launcher: Launcher, seconds: float) -> None:
    while True:
        try:
            await launcher.report_due()
        except Exception:  # noqa: BLE001 — a failed retry is retried
            logger.exception("report loop failed")
        await asyncio.sleep(seconds)


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="airlock launcher")
    parser.add_argument("--config", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--engine", default="claude", choices=("claude", "stub"), help="engine for task-mode steps")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    config = load_launcher(args.config)
    if config.runtime == "local":
        logger.warning("runtime: local — groups run as plain processes with NO isolation; tests and the demo only")
        runtime: DockerRuntime | LocalRuntime = LocalRuntime()
    else:
        runtime = DockerRuntime(config.docker_bin)
    launcher = Launcher(config, runtime, engine=args.engine)
    uvicorn.run(create_launcher_app(launcher), host=args.host, port=args.port)
