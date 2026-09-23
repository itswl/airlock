"""The control plane's HTTP surface: the pipe's intake, the machine callbacks, and the web console.

Three kinds of caller, three kinds of proof:

* sources prove themselves the way their platform signs (``/v1/intake/{source}``);
* investigators, the launcher and adapters sign with this system's timestamped HMAC,
  each with its own secret, so one leaked secret speaks for one party only;
* you log in, and every form that changes something carries a session-bound token.

The loop that dispatches, expires and launches runs in the same process. One
process, one SQLite file: the whole control plane is small enough to read.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import shlex
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from airlock import __version__
from airlock.config import ControlConfig
from airlock.control import auth
from airlock.control.intake import MAX_BODY_BYTES
from airlock.control.service import ControlPlane, Outcome
from airlock.crypto import PROFILE_HEADER, SignatureError, header, verify

logger = logging.getLogger("airlock.control.app")

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

STATE_LABELS = {
    "queued": "排队中",
    "investigating": "调查中",
    "answered": "已答复",
    "plan_ready": "等你决定",
    "approved": "已批准",
    "running": "执行中",
    "done": "已完成",
    "failed": "执行失败",
    "refused": "被拒执行",
    "cancelled": "已急停",
    "rejected": "已驳回",
    "closed": "已关闭",
    "error": "出错",
    "plan_invalid": "方案无效",
}


def _when(value: Any) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(value)))
    except (TypeError, ValueError):
        return ""


TEMPLATES.env.filters["when"] = _when
TEMPLATES.env.filters["pretty"] = lambda v: json.dumps(v, indent=2, ensure_ascii=False, sort_keys=True)
TEMPLATES.env.filters["argv"] = lambda v: shlex.join(str(a) for a in v or [])
TEMPLATES.env.globals["STATE_LABELS"] = STATE_LABELS
TEMPLATES.env.globals["version"] = __version__


class LoginRequired(Exception):
    pass


def create_app(
    config: ControlConfig,
    *,
    plane: ControlPlane | None = None,
    run_loop: bool = True,
    tick_seconds: float = 2.0,
) -> FastAPI:
    plane = plane or ControlPlane(config)
    throttle = auth.Throttle()

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(_loop(plane, tick_seconds)) if run_loop else None
        try:
            yield
        finally:
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(title="airlock control plane", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.plane = plane

    @app.exception_handler(LoginRequired)
    async def _login(request: Request, exc: LoginRequired) -> Response:
        return RedirectResponse("/login", status_code=303)

    # ------------------------------------------------------------------ machines

    async def signed_body(request: Request, secret: str) -> bytes:
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(413, "body too large")
        try:
            verify(secret, body, request.headers, now=plane.clock())
        except SignatureError as exc:
            raise HTTPException(401, str(exc)) from exc
        return body

    def as_json(body: bytes) -> dict[str, Any]:
        try:
            data = json.loads(body)
        except ValueError as exc:
            raise HTTPException(400, "the body is not JSON") from exc
        if not isinstance(data, dict):
            raise HTTPException(400, "the body must be a JSON object")
        return data

    def reply(outcome: Outcome) -> JSONResponse:
        return JSONResponse(outcome.body, status_code=outcome.status)

    async def investigator_call(request: Request) -> tuple[str, dict[str, Any]]:
        name = header(request.headers, PROFILE_HEADER)
        profile = config.investigators.get(name)
        if profile is None:
            raise HTTPException(401, "unknown investigator profile")
        return name, as_json(await signed_body(request, profile.secret))

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"ok": True, "version": __version__}

    @app.post("/v1/intake/{source}")
    async def intake(source: str, request: Request) -> JSONResponse:
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            return JSONResponse({"outcome": "invalid", "reason": "body too large"}, status_code=413)
        return reply(plane.intake(source, request.headers, body))

    @app.post("/v1/investigations/result")
    async def investigation_result(request: Request) -> JSONResponse:
        name, payload = await investigator_call(request)
        return reply(plane.receive_result(name, payload))

    @app.post("/v1/investigations/error")
    async def investigation_error(request: Request) -> JSONResponse:
        name, payload = await investigator_call(request)
        return reply(plane.receive_error(name, payload))

    @app.post("/v1/consult")
    async def consult(request: Request) -> JSONResponse:
        name, payload = await investigator_call(request)
        return reply(await plane.consult(name, payload))

    @app.post("/v1/runs/progress")
    async def run_progress(request: Request) -> JSONResponse:
        return reply(plane.receive_progress(as_json(await signed_body(request, config.launcher_secret))))

    @app.post("/v1/runs/result")
    async def run_result(request: Request) -> JSONResponse:
        return reply(plane.receive_run_result(as_json(await signed_body(request, config.launcher_secret))))

    @app.post("/v1/adapters/{name}/message")
    async def adapter_message(name: str, request: Request) -> JSONResponse:
        adapter = config.adapters.get(name)
        if adapter is None:
            raise HTTPException(404, "unknown adapter")
        return reply(plane.adapter_message(name, as_json(await signed_body(request, adapter.secret))))

    @app.post("/v1/adapters/{name}/decision")
    async def adapter_decision(name: str, request: Request) -> JSONResponse:
        adapter = config.adapters.get(name)
        if adapter is None:
            raise HTTPException(404, "unknown adapter")
        return reply(plane.adapter_decision(name, as_json(await signed_body(request, adapter.secret))))

    # ------------------------------------------------------------------ you

    def session(request: Request) -> str:
        cookie = request.cookies.get(auth.COOKIE)
        if auth.read_session(config.session_secret, cookie, now=plane.clock()) != config.operator.name:
            raise LoginRequired()
        return str(cookie)

    def checked(request: Request, token: str) -> None:
        cookie = session(request)
        if not auth.check_csrf(config.session_secret, cookie, token):
            raise HTTPException(403, "the form token does not match this session; reload the page")

    def page(request: Request, name: str, **context: Any) -> HTMLResponse:
        cookie = request.cookies.get(auth.COOKIE) or ""
        context.setdefault("flash", request.query_params.get("flash", ""))
        context["csrf"] = auth.csrf_token(config.session_secret, cookie) if cookie else ""
        context["operator"] = config.operator.name
        return TEMPLATES.TemplateResponse(request, name, context)

    def back(work_id: str, outcome: Outcome, done: str) -> RedirectResponse:
        text = done if outcome.ok else str(outcome.body.get("reason") or f"HTTP {outcome.status}")
        return RedirectResponse(f"/work/{work_id}?flash={quote(text)}", status_code=303)

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> HTMLResponse:
        return page(request, "login.html")

    @app.post("/login")
    async def login(request: Request, password: str = Form(...)) -> Response:
        who = request.client.host if request.client else "?"
        if throttle.blocked(who, plane.clock()):
            return page(request, "login.html", flash="尝试次数过多，请五分钟后再试")
        if not auth.check_password(password, config.operator.password_hash):
            throttle.failed(who, plane.clock())
            plane.ledger.append("login.failed", actor=f"web:{who}")
            return page(request, "login.html", flash="密码不对")
        throttle.succeeded(who)
        plane.ledger.append("login", actor=config.operator.name, data={"from": who})
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            auth.COOKIE,
            auth.make_session(config.session_secret, config.operator.name, now=plane.clock()),
            max_age=auth.SESSION_SECONDS,
            httponly=True,
            samesite="strict",
            secure=config.cookie_secure,
        )
        return response

    @app.post("/logout")
    async def logout(request: Request, csrf: str = Form("")) -> Response:
        checked(request, csrf)
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(auth.COOKIE)
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        session(request)
        items = plane.list_work()
        waiting = [w for w in items if w["state"] == "plan_ready"]
        others = [w for w in items if w["state"] != "plan_ready"]
        return page(request, "index.html", waiting=waiting, others=others)

    @app.post("/signals")
    async def manual_signal(
        request: Request, title: str = Form(""), body: str = Form(""), csrf: str = Form("")
    ) -> Response:
        checked(request, csrf)
        outcome = plane.manual_signal(title, body)
        if not outcome.ok:
            return RedirectResponse(f"/?flash={quote(str(outcome.body.get('reason')))}", status_code=303)
        return RedirectResponse(f"/work/{outcome.body['work_id']}", status_code=303)

    @app.get("/work/{work_id}", response_class=HTMLResponse)
    async def work_page(work_id: str, request: Request) -> HTMLResponse:
        session(request)
        detail = plane.detail(work_id)
        if detail is None:
            raise HTTPException(404, "no such work item")
        return page(request, "work.html", **detail, workers=config.workers)

    @app.post("/work/{work_id}/message")
    async def message(work_id: str, request: Request, text: str = Form(""), csrf: str = Form("")) -> Response:
        checked(request, csrf)
        outcome = plane.operator_message(work_id, text, via="web")
        done = "已发给调查员，它会按你的留言修订" if outcome.body.get("reopens") else "已记录"
        return back(work_id, outcome, done)

    @app.post("/work/{work_id}/approve")
    async def approve(
        work_id: str,
        request: Request,
        version: int = Form(...),
        plan_hash: str = Form(...),
        csrf: str = Form(""),
    ) -> Response:
        checked(request, csrf)
        return back(
            work_id, plane.approve(work_id, version=version, plan_hash_value=plan_hash, via="web"), "已批准，交给执行"
        )

    @app.post("/work/{work_id}/reject")
    async def reject(work_id: str, request: Request, reason: str = Form(""), csrf: str = Form("")) -> Response:
        checked(request, csrf)
        return back(work_id, plane.reject(work_id, via="web", reason=reason), "已驳回")

    @app.post("/work/{work_id}/close")
    async def close(work_id: str, request: Request, reason: str = Form(""), csrf: str = Form("")) -> Response:
        checked(request, csrf)
        return back(work_id, plane.close(work_id, via="web", reason=reason), "已关闭")

    @app.post("/work/{work_id}/revoke")
    async def revoke(work_id: str, request: Request, csrf: str = Form("")) -> Response:
        checked(request, csrf)
        return back(work_id, plane.revoke(work_id, via="web"), "已撤回批准")

    @app.post("/work/{work_id}/cancel")
    async def cancel(work_id: str, request: Request, csrf: str = Form("")) -> Response:
        checked(request, csrf)
        return back(work_id, await plane.cancel(work_id, via="web"), "已发出急停")

    @app.get("/ledger", response_class=HTMLResponse)
    async def ledger(request: Request) -> HTMLResponse:
        session(request)
        return page(request, "ledger.html", check=plane.ledger.verify(), entries=plane.ledger.entries(limit=300))

    @app.get("/events", response_class=HTMLResponse)
    async def events(request: Request) -> HTMLResponse:
        session(request)
        rows = plane.db.all("SELECT * FROM events ORDER BY id DESC LIMIT 300")
        return page(request, "events.html", rows=rows)

    @app.get("/outbox", response_class=HTMLResponse)
    async def outbox(request: Request) -> HTMLResponse:
        session(request)
        rows = plane.db.all("SELECT * FROM outbox ORDER BY id DESC LIMIT 300")
        return page(request, "outbox.html", rows=rows)

    return app


async def _loop(plane: ControlPlane, seconds: float) -> None:
    while True:
        try:
            await plane.tick()
        except Exception:  # noqa: BLE001 — one bad tick must not stop the next
            logger.exception("control loop tick failed")
        await asyncio.sleep(seconds)
