"""The control plane's logic. Every state change of a work item happens here, and each is in the ledger.

    queued -> investigating -> answered                  a report, nothing to run
                            -> plan_ready -> approved -> running -> done | failed | cancelled
                                   ^   |        |
                                   |   |        +-> plan_ready  you revoked it, or it expired
                                   +---+  a message from you: the investigator revises
                                          (a revision is a new version with a new hash)

    investigating -> plan_invalid   no approvable plan after the automatic revisions
    approved      -> refused        the launcher refused the plan
    plan_ready    -> rejected       you said no
    any open      -> closed         you closed it

Three rules are enforced here rather than configured, because each is the answer
to "is there any way around your approval":

* only the plan version you approved, identified by its hash, is handed on;
* only the investigator that owns a work item can consult another, one level deep;
* nothing here can start a worker. It can only ask the launcher, which checks again.
"""

from __future__ import annotations

import difflib
import json
import logging
import secrets
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from airlock.config import ControlConfig
from airlock.control import intake
from airlock.control.outbox import Outbox
from airlock.control.store import ACTIONS, CONCLUDED, REOPENS, SCHEMA, TERMINAL
from airlock.crypto import PROFILE_HEADER, SignatureError, canonical_json, sha256_hex, sign
from airlock.db import Database
from airlock.ledger import Ledger
from airlock.plans import PlanError, extract_plan, has_plan, plan_hash, strip_plans, validate_plan
from airlock.runner.gate import redact

logger = logging.getLogger("airlock.control")

DISPATCH_BACKOFF_SECONDS = (5, 15, 60, 180, 600)
LAUNCH_RETRY_SECONDS = 30
RUN_STATUSES = ("done", "failed", "refused", "cancelled")


@dataclass
class Outcome:
    status: int
    body: dict[str, Any]

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


def _workspace_summary(workspace: Mapping[str, Any]) -> dict[str, Any]:
    """What the ledger keeps of a group's change: which repository, how big, and the hash of the diff itself."""
    keep = ("repo", "start", "files_changed", "insertions", "deletions", "patch_sha256", "truncated", "error")
    return {k: workspace[k] for k in keep if k in workspace}


class ControlPlane:
    def __init__(
        self,
        config: ControlConfig,
        *,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self.clock = clock
        self.db = Database(config.db_path)
        self.db.script(SCHEMA)
        self.ledger = Ledger(self.db)
        self.outbox = Outbox(self.db, config.subscriptions)
        self.client = client or httpx.AsyncClient(timeout=httpx.Timeout(30.0, read=900.0))

    # ------------------------------------------------------------------ helpers

    @property
    def operator(self) -> str:
        return self.config.operator.name

    def link(self, work_id: str) -> str:
        return f"{self.config.base_url}/work/{work_id}"

    def work(self, work_id: Any) -> dict[str, Any] | None:
        row = self.db.one("SELECT * FROM work_items WHERE id = ?", [str(work_id or "")])
        if row is not None:
            row["labels"] = json.loads(row["labels"])
            row["fields"] = json.loads(row["fields"])
            row["actions"] = ACTIONS.get(row["state"], ())
        return row

    def _set(self, work_id: str, **fields: Any) -> None:
        fields["updated_at"] = self.clock()
        if "state" in fields:
            # When the work item last concluded — what a repeat of its signal is
            # measured against to decide whether it continues this session.
            fields["concluded_at"] = fields["updated_at"] if fields["state"] in CONCLUDED else None
        assignments = ", ".join(f"{name} = ?" for name in fields)
        self.db.execute(f"UPDATE work_items SET {assignments} WHERE id = ?", [*fields.values(), work_id])  # noqa: S608

    def _notify(self, event: str, work_id: str, **extra: Any) -> None:
        work = self.work(work_id) or {"title": "", "state": "", "actions": ()}
        payload = {
            "work_id": work_id,
            "title": work["title"],
            "state": work["state"],
            "actions": list(work["actions"]),
            "link": self.link(work_id),
            **extra,
        }
        self.outbox.enqueue(event, payload, now=self.clock())

    def _event(
        self,
        source: str,
        outcome: str,
        reason: str = "",
        *,
        key: str = "",
        title: str = "",
        work_id: str | None = None,
        digest: str = "",
    ) -> None:
        self.db.execute(
            "INSERT INTO events (source, received_at, outcome, reason, key, title, work_id, body_digest) "
            "VALUES (?,?,?,?,?,?,?,?)",
            [source, self.clock(), outcome, reason[:300], key[:300], title[:300], work_id, digest],
        )

    def _message(self, work_id: str, author: str, text: str, via: str) -> int:
        cursor = self.db.execute(
            "INSERT INTO messages (work_id, at, author, via, text) VALUES (?,?,?,?,?)",
            [work_id, self.clock(), author, via, text[:8000]],
        )
        return int(cursor.lastrowid or 0)

    async def _post(
        self,
        url: str,
        secret: str,
        payload: Mapping[str, Any],
        *,
        profile: str | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        body = canonical_json(dict(payload))
        headers = {**sign(secret, body, now=self.clock()), "Content-Type": "application/json"}
        if profile:
            headers[PROFILE_HEADER] = profile
        if timeout is None:
            return await self.client.post(url, content=body, headers=headers)
        return await self.client.post(url, content=body, headers=headers, timeout=timeout)

    def plan_row(self, work_id: str, version: int) -> dict[str, Any] | None:
        row = self.db.one("SELECT * FROM plans WHERE work_id = ? AND version = ?", [work_id, version])
        if row is not None:
            row["plan"] = json.loads(row["plan"])
            row["errors"] = json.loads(row["errors"])
        return row

    def _pending_approval(self, work_id: str) -> dict[str, Any] | None:
        return self.db.one(
            "SELECT * FROM approvals WHERE work_id = ? AND status IN ('approved', 'launched') ORDER BY at DESC LIMIT 1",
            [work_id],
        )

    # ------------------------------------------------------------------ intake

    def intake(self, source_name: str, headers: Mapping[str, str], body: bytes) -> Outcome:
        source = self.config.sources.get(source_name)
        if source is None:
            return Outcome(404, {"outcome": "unknown_source"})
        digest = sha256_hex(body)
        try:
            intake.verify_source(source, headers, body, now=self.clock())
        except SignatureError as exc:
            self._event(source_name, "rejected", str(exc), digest=digest)
            self.ledger.append("signal.rejected", actor=f"source:{source_name}", data={"reason": str(exc)})
            return Outcome(401, {"outcome": "rejected", "reason": str(exc)})
        try:
            payload = intake.parse(body)
        except (ValueError, UnicodeDecodeError) as exc:
            self._event(source_name, "invalid", str(exc), digest=digest)
            return Outcome(400, {"outcome": "invalid", "reason": str(exc)})
        signals = [
            intake.normalize(source, ctx)
            for ctx in intake.contexts(source, headers, payload)
            if intake.accepted(source, ctx)
        ]
        if not signals:
            self._event(source_name, "filtered", "no accept rule matched", digest=digest)
            return Outcome(200, {"outcome": "filtered"})
        results = [self._take(source, signal, digest) for signal in signals]
        started = any(r["outcome"] in ("accepted", "continued") for r in results)
        if source.split is None:
            return Outcome(202 if started else 200, results[0])
        return Outcome(202 if started else 200, {"outcome": "split", "signals": results})

    def _take(self, source: Any, signal: Mapping[str, Any], digest: str) -> dict[str, Any]:
        """One signal: join the open work item it repeats, continue one that just ended, or start fresh."""
        name, key, title = source.name, signal["key"], signal["title"]
        existing = self._open_work_with_key(name, key, source.dedup_seconds)
        if existing is not None:
            update = f"{title}\n\n{signal['body']}".strip()
            self._message(existing["id"], f"source:{name}", update, via="webhook")
            self.db.execute(
                "UPDATE work_items SET last_signal_at = ?, signals = signals + 1 WHERE id = ?",
                [self.clock(), existing["id"]],
            )
            self._event(name, "duplicate", key=key, title=title, work_id=existing["id"], digest=digest)
            self.ledger.append(
                "signal.duplicate",
                work_id=existing["id"],
                actor=f"source:{name}",
                data={"key": key, "signals": existing["signals"] + 1},
            )
            return {"outcome": "duplicate", "work_id": existing["id"]}
        investigator = intake.route(self.config, signal)
        if investigator is None:
            self._event(name, "unrouted", "no route matched", key=key, title=title, digest=digest)
            self.ledger.append("signal.unrouted", actor=f"source:{name}", data={"key": key, "title": title})
            return {"outcome": "unrouted"}
        previous = self._concluded_with_key(name, key, source.continue_seconds, investigator)
        work_id = self.create_work(signal, investigator, actor=f"source:{name}", continues=previous)
        outcome = "continued" if previous else "accepted"
        self._event(name, outcome, key=key, title=title, work_id=work_id, digest=digest)
        return {"outcome": outcome, "work_id": work_id, **({"continues": previous["id"]} if previous else {})}

    def _open_work_with_key(self, source: str, key: str, window: int) -> dict[str, Any] | None:
        """The open work item this signal repeats, if its last signal is recent enough."""
        placeholders = ",".join("?" * len(TERMINAL))
        query = f"SELECT id FROM work_items WHERE source = ? AND key = ? AND last_signal_at >= ? AND state NOT IN ({placeholders}) ORDER BY last_signal_at DESC LIMIT 1"  # noqa: S608
        row = self.db.one(query, [source, key, self.clock() - window, *TERMINAL])
        return self.work(row["id"]) if row else None

    def _concluded_with_key(self, source: str, key: str, window: int, investigator: str) -> dict[str, Any] | None:
        """The work item this signal is a sequel to: same key, same investigator, concluded within the window."""
        if window <= 0:
            return None
        placeholders = ",".join("?" * len(CONCLUDED))
        query = f"SELECT id FROM work_items WHERE source = ? AND key = ? AND investigator = ? AND concluded_at >= ? AND state IN ({placeholders}) ORDER BY concluded_at DESC LIMIT 1"  # noqa: S608
        row = self.db.one(query, [source, key, investigator, self.clock() - window, *CONCLUDED])
        return self.work(row["id"]) if row else None

    def create_work(
        self, signal: Mapping[str, Any], investigator: str, *, actor: str, continues: Mapping[str, Any] | None = None
    ) -> str:
        work_id = uuid.uuid4().hex[:12]
        now = self.clock()
        self.db.execute(
            "INSERT INTO work_items (id, created_at, updated_at, last_signal_at, continues, session_hint, source, key, "
            "title, url, body, labels, fields, investigator, state) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                work_id,
                now,
                now,
                now,
                continues["id"] if continues else None,
                f"fork:{continues['id']}" if continues else "",
                signal["source"],
                signal["key"],
                signal["title"],
                signal.get("url", ""),
                signal.get("body", ""),
                json.dumps(list(signal.get("labels") or [])),
                json.dumps({"event": signal.get("event", "")}),
                investigator,
                "queued",
            ],
        )
        self.ledger.append(
            "work.created",
            work_id=work_id,
            actor=actor,
            data={
                "source": signal["source"],
                "key": signal["key"],
                "title": signal["title"],
                "investigator": investigator,
                "continues": continues["id"] if continues else None,
            },
        )
        if continues is not None and continues["state"] == "answered":
            # A report nobody closed, now superseded by the sequel that continues it.
            self._set(continues["id"], state="closed", note=f"continued in {work_id}")
            self.ledger.append("work.superseded", work_id=continues["id"], data={"by": work_id})
        self._notify(
            "work.created", work_id, investigator=investigator, continues=continues["id"] if continues else None
        )
        return work_id

    def manual_signal(self, title: str, body: str) -> Outcome:
        title, body = title.strip()[:300], body.strip()[:20000]
        if not title:
            return Outcome(400, {"reason": "a title is required"})
        signal = {
            "source": "web",
            "event": "manual",
            "title": title,
            "body": body,
            "url": "",
            "key": uuid.uuid4().hex,
            "labels": ["manual"],
        }
        investigator = intake.route(self.config, signal)
        if investigator is None:
            return Outcome(422, {"reason": "no route sends web signals to an investigator"})
        return Outcome(202, {"work_id": self.create_work(signal, investigator, actor=self.operator)})

    # ------------------------------------------------------------------ investigation

    async def dispatch_due(self) -> int:
        rows = self.db.all(
            "SELECT id FROM work_items WHERE state = 'queued' AND next_dispatch_at <= ? ORDER BY created_at LIMIT 10",
            [self.clock()],
        )
        for row in rows:
            await self._dispatch(row["id"])
        return len(rows)

    def _catalogue(self, investigator: str) -> dict[str, Any]:
        """What an investigator needs to write a plan the launcher will accept, and whom it may ask."""
        return {
            "workers": [
                {
                    "name": w.name,
                    "modes": list(w.modes),
                    "command_allowlist": list(w.command_allowlist),
                    "allowed_permissions": list(w.allowed_permissions),
                }
                for w in self.config.workers.values()
            ],
            "consultable": list(self.config.investigators[investigator].may_consult),
        }

    def _investigation_payload(self, work: Mapping[str, Any]) -> dict[str, Any]:
        latest = self.plan_row(work["id"], work["current_version"]) if work["current_version"] else None
        last = self.db.one("SELECT errors FROM plans WHERE work_id = ? ORDER BY version DESC LIMIT 1", [work["id"]])
        messages = self.db.all(
            "SELECT id, author, via, text, at FROM messages WHERE work_id = ? ORDER BY id", [work["id"]]
        )
        return {
            "work_id": work["id"],
            "signal": {k: work[k] for k in ("source", "key", "title", "url", "body", "labels", "fields")},
            "signals": work["signals"],
            "messages": messages,
            "latest_plan": latest["plan"] if latest else None,
            "latest_version": work["current_version"],
            "latest_errors": json.loads(last["errors"]) if last else [],
            "note": work["note"],
            "session": session_directive(work["session_hint"]),
            "continues": self._sequel_of(work["continues"]) if work["continues"] else None,
            **self._catalogue(work["investigator"]),
        }

    def _sequel_of(self, work_id: str) -> dict[str, Any] | None:
        """What an investigator needs to know about the work item it is continuing."""
        previous = self.work(work_id)
        if previous is None:
            return None
        plan = self.plan_row(work_id, previous["current_version"]) if previous["current_version"] else None
        run = self.db.one("SELECT status FROM runs WHERE work_id = ? ORDER BY received_at DESC LIMIT 1", [work_id])
        return {
            "work_id": work_id,
            "title": previous["title"],
            "state": previous["state"],
            "note": previous["note"],
            "concluded_at": previous["concluded_at"],
            "plan_summary": plan["plan"]["summary"] if plan else None,
            "run_status": run["status"] if run else None,
        }

    async def _dispatch(self, work_id: str) -> None:
        work = self.work(work_id)
        if work is None or work["state"] != "queued":
            return
        profile = self.config.investigators.get(work["investigator"])
        if profile is None:
            self._set(work_id, state="error", note="the investigator profile no longer exists")
            self.ledger.append("investigation.failed", work_id=work_id, data={"reason": "profile missing"})
            self._notify("work.error", work_id)
            return
        payload = self._investigation_payload(work)
        seen = max((m["id"] for m in payload["messages"]), default=0)
        self._set(work_id, state="investigating", last_seen_message=seen, dispatched_at=self.clock())
        # Recorded before the call: the answer can arrive before this coroutine resumes.
        attempt = work["dispatch_attempts"] + 1
        self.ledger.append(
            "investigation.dispatched", work_id=work_id, data={"investigator": profile.name, "attempt": attempt}
        )
        error = ""
        try:
            response = await self._post(f"{profile.url}/investigate", profile.secret, payload)
            if response.status_code in (200, 202):
                # The directive was delivered; later rounds resume this item's own session.
                self._set(work_id, dispatch_attempts=0, session_hint="")
                return
            error = f"HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            error = f"{type(exc).__name__}: {exc}"[:300]
        self.ledger.append("investigation.dispatch_failed", work_id=work_id, data={"reason": error, "attempt": attempt})
        current = self.work(work_id)
        if current is None or current["state"] != "investigating":
            return
        attempts = attempt
        if attempts >= len(DISPATCH_BACKOFF_SECONDS):
            self._set(work_id, state="error", dispatch_attempts=attempts, note=f"investigator unreachable: {error}")
            self.ledger.append("investigation.failed", work_id=work_id, data={"reason": error, "attempts": attempts})
            self._notify("work.error", work_id, reason=error)
        else:
            self._set(
                work_id,
                state="queued",
                dispatch_attempts=attempts,
                next_dispatch_at=self.clock() + DISPATCH_BACKOFF_SECONDS[attempts - 1],
                note=f"retrying: {error}",
            )

    def _owned_investigation(self, profile: str, work_id: Any) -> tuple[dict[str, Any] | None, Outcome | None]:
        work = self.work(work_id)
        if work is None:
            return None, Outcome(404, {"reason": "no such work item"})
        if work["investigator"] != profile:
            return None, Outcome(403, {"reason": "this work item belongs to another investigator"})
        if work["state"] != "investigating":
            return None, Outcome(409, {"reason": f"the work item is {work['state']}, not investigating"})
        return work, None

    def _unread_from_operator(self, work: Mapping[str, Any]) -> bool:
        row = self.db.one(
            "SELECT 1 FROM messages WHERE work_id = ? AND author = ? AND id > ? LIMIT 1",
            [work["id"], self.operator, work["last_seen_message"]],
        )
        return row is not None

    def _settle(self, work: Mapping[str, Any], state: str, note: str = "") -> str:
        """Land an investigation's outcome, unless you wrote while it ran: then it goes round again."""
        if self._unread_from_operator(work):
            self._set(work["id"], state="queued", next_dispatch_at=self.clock(), note="answering your newer message")
            self.ledger.append(
                "investigation.requeued", work_id=work["id"], data={"reason": "operator wrote during it"}
            )
            return "queued"
        self._set(work["id"], state=state, note=note)
        return state

    def receive_result(self, profile: str, payload: Mapping[str, Any]) -> Outcome:
        work, refused = self._owned_investigation(profile, payload.get("work_id"))
        if refused is not None:
            return refused
        assert work is not None
        text = str(payload.get("text") or "")
        usage = {k: payload[k] for k in ("cost_usd", "turns", "refusals", "usage") if k in payload}
        if payload.get("session"):
            self.db.execute(
                "UPDATE work_items SET engine_session = ? WHERE id = ?", [str(payload["session"])[:200], work["id"]]
            )
        prose = strip_plans(text)
        if prose:
            self._message(work["id"], f"investigator:{profile}", prose, via="investigation")
        if not has_plan(text):
            return self._answered(work, profile, usage)
        try:
            plan = extract_plan(text)
            errors = validate_plan(plan, self.config.workers)
        except PlanError as exc:
            plan, errors = None, [str(exc)]
        if plan is not None and not errors:
            return self._plan_ready(work, profile, plan, usage)
        version = None
        if plan is not None:
            version = self._store_plan(work["id"], profile, plan, errors)
        self.ledger.append(
            "plan.invalid",
            work_id=work["id"],
            actor=f"investigator:{profile}",
            data={"errors": errors, "version": version},
        )
        if work["auto_revisions"] < self.config.max_auto_revisions:
            feedback = (
                "This plan cannot be shown for approval yet. Fix these and send the whole plan again:\n- "
                + "\n- ".join(errors)
            )
            self._message(work["id"], "system", feedback, via="validation")
            self._set(
                work["id"],
                state="queued",
                auto_revisions=work["auto_revisions"] + 1,
                next_dispatch_at=self.clock(),
                note="revision requested",
            )
            return Outcome(200, {"status": "revision_requested", "errors": errors})
        state = self._settle(work, "plan_invalid", "; ".join(errors)[:1000])
        if state == "plan_invalid":
            self._notify("plan.invalid", work["id"], errors=errors)
        return Outcome(200, {"status": state, "errors": errors})

    def _store_plan(self, work_id: str, profile: str, plan: Any, errors: list[str]) -> int:
        top = self.db.one("SELECT MAX(version) AS v FROM plans WHERE work_id = ?", [work_id]) or {}
        version = int(top.get("v") or 0) + 1
        self.db.execute(
            "INSERT INTO plans (work_id, version, created_at, author, plan, plan_hash, errors) VALUES (?,?,?,?,?,?,?)",
            [
                work_id,
                version,
                self.clock(),
                f"investigator:{profile}",
                canonical_json(plan.model_dump(mode="json")).decode(),
                plan_hash(plan),
                json.dumps(errors),
            ],
        )
        return version

    def _answered(self, work: Mapping[str, Any], profile: str, usage: Mapping[str, Any]) -> Outcome:
        """No plan in the reply. With a plan already standing, it was an answer about that plan."""
        target = "plan_ready" if work["current_version"] else "answered"
        state = self._settle(work, target)
        self.ledger.append(
            "investigation.answered",
            work_id=work["id"],
            actor=f"investigator:{profile}",
            data={"plan_version": work["current_version"], **usage},
        )
        if state != "queued":
            self._notify("work.answered", work["id"], plan_version=work["current_version"])
        return Outcome(200, {"status": state})

    def _plan_ready(self, work: Mapping[str, Any], profile: str, plan: Any, usage: Mapping[str, Any]) -> Outcome:
        digest = plan_hash(plan)
        current = self.plan_row(work["id"], work["current_version"]) if work["current_version"] else None
        if current is not None and current["plan_hash"] == digest:
            version, changed = work["current_version"], False
        else:
            version, changed = self._store_plan(work["id"], profile, plan, []), True
        self._set(work["id"], current_version=version, auto_revisions=0)
        self.ledger.append(
            "plan.ready",
            work_id=work["id"],
            actor=f"investigator:{profile}",
            data={
                "version": version,
                "plan_hash": digest,
                "changed": changed,
                "risk": plan.risk,
                "workers": sorted({s.worker for s in plan.steps}),
                **usage,
            },
        )
        state = self._settle({**work, "current_version": version}, "plan_ready")
        if state == "plan_ready":
            self._notify(
                "plan.revised" if current is not None and changed else "plan.ready",
                work["id"],
                version=version,
                plan_hash=digest,
                summary=plan.summary,
                risk=plan.risk,
                changed=changed,
            )
        return Outcome(200, {"status": state, "version": version})

    def receive_error(self, profile: str, payload: Mapping[str, Any]) -> Outcome:
        work, refused = self._owned_investigation(profile, payload.get("work_id"))
        if refused is not None:
            return refused
        assert work is not None
        reason = str(payload.get("error") or "the investigation failed")[:1000]
        self._set(work["id"], state="error", note=reason)
        self.ledger.append(
            "investigation.failed", work_id=work["id"], actor=f"investigator:{profile}", data={"reason": reason}
        )
        self._notify("work.error", work["id"], reason=reason)
        return Outcome(200, {"status": "error"})

    async def consult(self, from_profile: str, payload: Mapping[str, Any]) -> Outcome:
        """One investigator asks another. Only the owner of a live investigation may ask; the answer comes back redacted."""
        work, refused = self._owned_investigation(from_profile, payload.get("work_id"))
        if refused is not None:
            return refused
        assert work is not None
        to = str(payload.get("to") or "")
        question, question_flags = redact(str(payload.get("question") or "").strip()[:4000])
        if not question:
            return Outcome(400, {"reason": "the question is empty"})
        if to not in self.config.investigators[from_profile].may_consult:
            self.ledger.append(
                "consult.refused", work_id=work["id"], actor=f"investigator:{from_profile}", data={"to": to[:64]}
            )
            return Outcome(403, {"reason": f"{from_profile} may not consult {to or 'nobody named'}"})
        asked = (self.db.one("SELECT COUNT(*) AS n FROM consults WHERE work_id = ?", [work["id"]]) or {"n": 0})["n"]
        if asked >= self.config.max_consults:
            return Outcome(429, {"reason": f"this work item has used its {self.config.max_consults} consults"})
        cursor = self.db.execute(
            "INSERT INTO consults (work_id, at, from_profile, to_profile, question, status) VALUES (?,?,?,?,?,?)",
            [work["id"], self.clock(), from_profile, to, question, "asked"],
        )
        consult_id = cursor.lastrowid
        self.ledger.append(
            "consult.asked",
            work_id=work["id"],
            actor=f"investigator:{from_profile}",
            data={"to": to, "consult": consult_id, "flags": question_flags},
        )
        target = self.config.investigators[to]
        try:
            response = await self._post(
                f"{target.url}/consult",
                target.secret,
                {
                    "work_id": work["id"],
                    "from": from_profile,
                    "question": question,
                    "context": {"title": work["title"], "source": work["source"]},
                },
                timeout=900,
            )
            if response.status_code != 200:
                raise httpx.HTTPStatusError(f"HTTP {response.status_code}", request=response.request, response=response)
            reply = response.json()
            answer = str(reply.get("answer") or "")
            spent = {k: reply[k] for k in ("cost_usd", "turns", "usage") if k in reply}
        except (httpx.HTTPError, ValueError) as exc:
            self.db.execute(
                "UPDATE consults SET status = 'failed', answered_at = ? WHERE id = ?", [self.clock(), consult_id]
            )
            self.ledger.append(
                "consult.failed", work_id=work["id"], data={"consult": consult_id, "reason": str(exc)[:200]}
            )
            return Outcome(502, {"reason": f"{to} could not answer"})
        clean, flags = redact(answer[:20000])
        self.db.execute(
            "UPDATE consults SET status = 'answered', answer = ?, answered_at = ?, flags = ? WHERE id = ?",
            [clean, self.clock(), json.dumps(flags), consult_id],
        )
        self.ledger.append(
            "consult.answered",
            work_id=work["id"],
            actor=f"investigator:{to}",
            data={"consult": consult_id, "flags": flags, **spent},
        )
        return Outcome(200, {"answer": clean, "flags": flags})

    # ------------------------------------------------------------------ you

    def operator_message(self, work_id: str, text: str, *, via: str) -> Outcome:
        work = self.work(work_id)
        if work is None:
            return Outcome(404, {"reason": "no such work item"})
        text = text.strip()
        if not text:
            return Outcome(400, {"reason": "the message is empty"})
        self._message(work_id, self.operator, text, via)
        reopens = work["state"] in REOPENS
        self.ledger.append(
            "message", work_id=work_id, actor=self.operator, data={"via": via, "chars": len(text), "reopens": reopens}
        )
        if reopens:
            self._set(
                work_id,
                state="queued",
                next_dispatch_at=self.clock(),
                auto_revisions=0,
                dispatch_attempts=0,
                note="revision asked for",
            )
        return Outcome(200, {"status": "recorded", "reopens": reopens})

    def approve(self, work_id: str, *, version: int, plan_hash_value: str, via: str) -> Outcome:
        """Your one click. It names the version and hash you read; anything else is refused."""
        work = self.work(work_id)
        if work is None:
            return Outcome(404, {"reason": "no such work item"})
        if work["state"] != "plan_ready":
            return Outcome(409, {"reason": f"nothing is waiting for approval; the work item is {work['state']}"})
        if int(version) != work["current_version"]:
            return Outcome(409, {"reason": "this is not the latest version of the plan"})
        row = self.plan_row(work_id, int(version))
        if row is None or row["plan_hash"] != plan_hash_value:
            return Outcome(409, {"reason": "the plan changed since you read it"})
        if row["errors"]:
            return Outcome(409, {"reason": "this version cannot be approved"})
        approval_id, now = secrets.token_hex(8), self.clock()
        expires_at = now + self.config.approval_ttl_seconds
        self.db.execute(
            "INSERT INTO approvals (id, work_id, version, plan_hash, approver, via, at, expires_at, status) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            [approval_id, work_id, int(version), plan_hash_value, self.operator, via, now, expires_at, "approved"],
        )
        self._set(work_id, state="approved", note="")
        self.ledger.append(
            "approval.granted",
            work_id=work_id,
            actor=self.operator,
            data={
                "approval": approval_id,
                "version": int(version),
                "plan_hash": plan_hash_value,
                "via": via,
                "expires_at": expires_at,
            },
        )
        self._notify("work.approved", work_id, version=int(version), plan_hash=plan_hash_value, via=via)
        return Outcome(200, {"status": "approved", "approval_id": approval_id})

    def reject(self, work_id: str, *, via: str, reason: str = "") -> Outcome:
        work = self.work(work_id)
        if work is None:
            return Outcome(404, {"reason": "no such work item"})
        if work["state"] != "plan_ready":
            return Outcome(409, {"reason": f"there is no plan waiting; the work item is {work['state']}"})
        self._set(work_id, state="rejected", note=reason[:500])
        self.ledger.append(
            "approval.rejected",
            work_id=work_id,
            actor=self.operator,
            data={"via": via, "version": work["current_version"], "reason": reason[:500]},
        )
        self._notify("work.rejected", work_id, via=via)
        return Outcome(200, {"status": "rejected"})

    def close(self, work_id: str, *, via: str, reason: str = "") -> Outcome:
        work = self.work(work_id)
        if work is None:
            return Outcome(404, {"reason": "no such work item"})
        if "close" not in work["actions"]:
            return Outcome(409, {"reason": f"a work item that is {work['state']} cannot be closed"})
        self._set(work_id, state="closed", note=reason[:500])
        self.ledger.append(
            "work.closed", work_id=work_id, actor=self.operator, data={"via": via, "from": work["state"]}
        )
        self._notify("work.closed", work_id, via=via)
        return Outcome(200, {"status": "closed"})

    def fresh(self, work_id: str, *, via: str) -> Outcome:
        """Investigate again from nothing: a new engine session, nothing carried over but the record."""
        work = self.work(work_id)
        if work is None:
            return Outcome(404, {"reason": "no such work item"})
        if "fresh" not in work["actions"]:
            return Outcome(409, {"reason": f"a work item that is {work['state']} cannot start over"})
        self._set(
            work_id,
            state="queued",
            session_hint="fresh",
            next_dispatch_at=self.clock(),
            auto_revisions=0,
            dispatch_attempts=0,
            note="starting over in a new session",
        )
        self.ledger.append("investigation.fresh", work_id=work_id, actor=self.operator, data={"via": via})
        return Outcome(200, {"status": "queued"})

    def revoke(self, work_id: str, *, via: str) -> Outcome:
        """Take an approval back before the launcher has it. After that, cancel the run instead."""
        work = self.work(work_id)
        approval = self._pending_approval(work_id) if work else None
        if work is None or approval is None or work["state"] != "approved" or approval["status"] != "approved":
            return Outcome(409, {"reason": "there is no approval waiting to launch"})
        self.db.execute(
            "UPDATE approvals SET status = 'revoked', note = ? WHERE id = ?", [f"revoked via {via}", approval["id"]]
        )
        self._set(work_id, state="plan_ready", note="you took the approval back")
        self.ledger.append(
            "approval.revoked", work_id=work_id, actor=self.operator, data={"approval": approval["id"], "via": via}
        )
        self._notify("approval.revoked", work_id, approval_id=approval["id"])
        return Outcome(200, {"status": "revoked"})

    async def cancel(self, work_id: str, *, via: str) -> Outcome:
        """Stop a running operation. The launcher kills the container; the run then reports itself cancelled."""
        work = self.work(work_id)
        approval = self._pending_approval(work_id) if work else None
        if work is None or approval is None or work["state"] != "running" or approval["status"] != "launched":
            return Outcome(409, {"reason": "nothing is running"})
        try:
            response = await self._post(
                f"{self.config.launcher_url}/cancel", self.config.launcher_secret, {"approval_id": approval["id"]}
            )
        except httpx.HTTPError as exc:
            return Outcome(502, {"reason": f"the launcher could not be reached: {type(exc).__name__}"})
        self.ledger.append(
            "run.cancel_requested",
            work_id=work_id,
            actor=self.operator,
            data={"approval": approval["id"], "via": via, "launcher": response.status_code},
        )
        if response.status_code != 200:
            return Outcome(502, {"reason": f"the launcher answered HTTP {response.status_code}"})
        return Outcome(200, {"status": "cancelling"})

    def _adapter_operator(self, adapter_name: str, payload: Mapping[str, Any]) -> Outcome | None:
        """An adapter speaks for you only when the platform user is one you mapped to yourself."""
        adapter = self.config.adapters.get(adapter_name)
        user = str(payload.get("platform_user") or "")
        if adapter is None or not user or user not in adapter.identities:
            self.ledger.append("adapter.identity_refused", actor=f"adapter:{adapter_name}", data={"user": user[:80]})
            return Outcome(403, {"reason": "this platform user is not mapped to the operator"})
        return None

    def adapter_message(self, adapter_name: str, payload: Mapping[str, Any]) -> Outcome:
        refused = self._adapter_operator(adapter_name, payload)
        if refused is not None:
            return refused
        return self.operator_message(
            str(payload.get("work_id") or ""), str(payload.get("text") or ""), via=f"adapter:{adapter_name}"
        )

    def adapter_decision(self, adapter_name: str, payload: Mapping[str, Any]) -> Outcome:
        refused = self._adapter_operator(adapter_name, payload)
        if refused is not None:
            return refused
        work_id, via = str(payload.get("work_id") or ""), f"adapter:{adapter_name}"
        decision = payload.get("decision")
        if decision == "reject":
            return self.reject(work_id, via=via, reason=str(payload.get("reason") or ""))
        if decision != "approve":
            return Outcome(400, {"reason": "decision must be approve or reject"})
        try:
            version = int(payload.get("version") or 0)
        except (TypeError, ValueError):
            return Outcome(400, {"reason": "version must be a number"})
        return self.approve(work_id, version=version, plan_hash_value=str(payload.get("plan_hash") or ""), via=via)

    def expire_investigations(self) -> int:
        """An investigation that never reported back — its node restarted, or hung — becomes an error you can see."""
        cutoff = self.clock() - self.config.investigation_timeout_seconds
        rows = self.db.all("SELECT id FROM work_items WHERE state = 'investigating' AND dispatched_at < ?", [cutoff])
        for row in rows:
            note = f"the investigator did not report back within {self.config.investigation_timeout_seconds}s"
            self._set(row["id"], state="error", note=note)
            self.ledger.append(
                "investigation.timed_out", work_id=row["id"], data={"after": self.config.investigation_timeout_seconds}
            )
            self._notify("work.error", row["id"], reason=note)
        return len(rows)

    def expire_approvals(self) -> int:
        rows = self.db.all("SELECT * FROM approvals WHERE status = 'approved' AND expires_at < ?", [self.clock()])
        for row in rows:
            self.db.execute("UPDATE approvals SET status = 'expired' WHERE id = ?", [row["id"]])
            work = self.work(row["work_id"])
            if work is not None and work["state"] == "approved":
                self._set(row["work_id"], state="plan_ready", note="the approval expired before it launched")
            self.ledger.append("approval.expired", work_id=row["work_id"], data={"approval": row["id"]})
            self._notify("approval.expired", row["work_id"], approval_id=row["id"])
        return len(rows)

    # ------------------------------------------------------------------ launch

    async def launch_due(self) -> int:
        rows = self.db.all(
            "SELECT a.id FROM approvals a JOIN work_items w ON w.id = a.work_id "
            "WHERE a.status = 'approved' AND a.next_launch_at <= ? AND a.expires_at >= ? AND w.state = 'approved'",
            [self.clock(), self.clock()],
        )
        for row in rows:
            await self._launch(row["id"])
        return len(rows)

    async def _launch(self, approval_id: str) -> None:
        approval = self.db.one("SELECT * FROM approvals WHERE id = ?", [approval_id])
        if approval is None:
            return
        row = self.plan_row(approval["work_id"], approval["version"])
        if row is None or row["plan_hash"] != approval["plan_hash"]:
            self._refuse_launch(approval, "the approved plan version is missing or changed")
            return
        body = {
            "approval": {
                k: approval[k] for k in ("id", "work_id", "version", "plan_hash", "approver", "via", "at", "expires_at")
            },
            "plan": row["plan"],
        }
        try:
            response = await self._post(f"{self.config.launcher_url}/launch", self.config.launcher_secret, body)
        except httpx.HTTPError as exc:
            self._retry_launch(approval, f"launcher unreachable: {type(exc).__name__}")
            return
        try:
            answer = response.json()
        except ValueError:
            answer = {}
        reason = str(answer.get("reason") or "") if isinstance(answer, dict) else ""
        # "already launched" is the launcher remembering this approval: an earlier
        # attempt got through even though its answer did not. The run is real.
        if response.status_code == 202 or (response.status_code == 409 and reason.startswith("already launched")):
            self.db.execute("UPDATE approvals SET status = 'launched', note = '' WHERE id = ?", [approval_id])
            self._set(approval["work_id"], state="running", note="")
            self.ledger.append("run.launched", work_id=approval["work_id"], data={"approval": approval_id})
            self._notify("run.started", approval["work_id"], approval_id=approval_id)
        elif response.status_code == 409 and reason.startswith("busy"):
            self._retry_launch(approval, reason)
        else:
            self._refuse_launch(approval, reason or f"launcher answered HTTP {response.status_code}")

    def _retry_launch(self, approval: Mapping[str, Any], note: str) -> None:
        self.db.execute(
            "UPDATE approvals SET launch_attempts = launch_attempts + 1, next_launch_at = ?, note = ? WHERE id = ?",
            [self.clock() + LAUNCH_RETRY_SECONDS, note[:300], approval["id"]],
        )
        self._set(approval["work_id"], note=f"waiting to launch: {note}"[:300])

    def _refuse_launch(self, approval: Mapping[str, Any], reason: str) -> None:
        self.db.execute(
            "UPDATE approvals SET status = 'refused', note = ? WHERE id = ?", [reason[:500], approval["id"]]
        )
        self._set(approval["work_id"], state="refused", note=reason[:500])
        self.ledger.append(
            "run.refused", work_id=approval["work_id"], data={"approval": approval["id"], "reason": reason[:500]}
        )
        self._notify("run.refused", approval["work_id"], approval_id=approval["id"], reason=reason[:500])

    def _launched(self, payload: Mapping[str, Any]) -> tuple[dict[str, Any] | None, Outcome | None]:
        approval = self.db.one("SELECT * FROM approvals WHERE id = ?", [str(payload.get("approval_id") or "")])
        if approval is None:
            return None, Outcome(404, {"reason": "no such approval"})
        if payload.get("plan_hash") != approval["plan_hash"]:
            return None, Outcome(409, {"reason": "this report is for a different plan"})
        return approval, None

    def receive_progress(self, payload: Mapping[str, Any]) -> Outcome:
        """One event from a running group, as it happens: what ran, where, and how it ended."""
        approval, refused = self._launched(payload)
        if refused is not None:
            return refused
        assert approval is not None
        if approval["status"] != "launched":
            return Outcome(409, {"reason": f"the approval is {approval['status']}, not launched"})
        event = str(payload.get("event") or "")[:40]
        step = payload.get("step") if isinstance(payload.get("step"), dict) else {}
        detail, _ = redact(str(step.get("command") or step.get("detail") or "")[:2000])
        tail, _ = redact(str(step.get("tail") or "")[-4000:])
        self.db.execute(
            "INSERT INTO run_steps (approval_id, work_id, at, group_index, worker, event, step_index, target, detail, "
            "status, exit_code, duration_ms, tail) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                approval["id"],
                approval["work_id"],
                self.clock(),
                int(payload.get("group") or 0),
                str(payload.get("worker") or "")[:64],
                event,
                step.get("index"),
                str(step.get("target") or "")[:200],
                detail,
                str(step.get("status") or "")[:40],
                step.get("exit_code"),
                step.get("duration_ms"),
                tail,
            ],
        )
        if event in ("step.end", "step.refused", "posture.failed", "tool.refused"):
            self.ledger.append(
                f"run.{event}",
                work_id=approval["work_id"],
                actor=f"worker:{str(payload.get('worker') or '')[:64]}",
                data={
                    "approval": approval["id"],
                    "group": payload.get("group"),
                    "step": step.get("index"),
                    "target": str(step.get("target") or "")[:200],
                    "detail": detail[:500],
                    "exit_code": step.get("exit_code"),
                    "duration_ms": step.get("duration_ms"),
                    "output_sha256": step.get("output_sha256"),
                },
            )
        return Outcome(200, {"status": "recorded"})

    def receive_run_result(self, payload: Mapping[str, Any]) -> Outcome:
        approval, refused = self._launched(payload)
        if refused is not None:
            return refused
        assert approval is not None
        if self.db.one("SELECT 1 FROM runs WHERE approval_id = ?", [approval["id"]]):
            return Outcome(200, {"status": "already recorded"})
        if approval["status"] != "launched":
            return Outcome(409, {"reason": f"the approval is {approval['status']}, not launched"})
        status = str(payload.get("status") or "failed")
        if status not in RUN_STATUSES:
            status = "failed"
        groups = [
            {
                "worker": g.get("worker"),
                "status": g.get("status"),
                "isolation": g.get("isolation"),
                "record_head": g.get("record_head"),
                "record_intact": g.get("record_intact"),
                "steps": len(g.get("steps") or []),
                **({"workspace": _workspace_summary(g["workspace"])} if isinstance(g.get("workspace"), dict) else {}),
            }
            for g in payload.get("groups") or []
            if isinstance(g, dict)
        ]
        clean, _ = redact(json.dumps(dict(payload), ensure_ascii=False))
        self.db.execute(
            "INSERT INTO runs (approval_id, work_id, received_at, status, result) VALUES (?,?,?,?,?)",
            [approval["id"], approval["work_id"], self.clock(), status, clean],
        )
        self.db.execute("UPDATE approvals SET status = 'finished' WHERE id = ?", [approval["id"]])
        self._set(approval["work_id"], state=status, note=str(payload.get("reason") or "")[:500])
        self.ledger.append(
            "run.finished",
            work_id=approval["work_id"],
            actor="launcher",
            data={"approval": approval["id"], "status": status, "groups": groups},
        )
        self._notify(
            "run.finished" if status == "done" else f"run.{status}",
            approval["work_id"],
            approval_id=approval["id"],
            status=status,
            groups=groups,
        )
        self.checkpoint(work_id=approval["work_id"])
        return Outcome(200, {"status": "recorded"})

    def checkpoint(self, *, work_id: str | None = None) -> dict[str, Any]:
        """Hand the ledger's head to whoever keeps it (a witness subscribed to ledger.checkpoint).

        A ledger edited after this can no longer show this hash at this seq,
        even if somebody rebuilt a self-consistent chain around the edit.
        """
        last = self.ledger.last()
        payload = {"seq": last["seq"], "head": last["hash"], "ledger_ts": last["ts"], "work_id": work_id}
        self.outbox.enqueue("ledger.checkpoint", payload, now=self.clock())
        self.db.execute(
            "INSERT INTO meta (key, value) VALUES ('checkpoint', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [json.dumps({"seq": last["seq"], "at": self.clock()})],
        )
        return payload

    def checkpoint_due(self) -> dict[str, Any] | None:
        """A checkpoint every ``checkpoint_seconds`` while the ledger grows, runs or no runs."""
        row = self.db.one("SELECT value FROM meta WHERE key = 'checkpoint'")
        previous = json.loads(row["value"]) if row else {"seq": 0, "at": 0.0}
        if self.ledger.last()["seq"] <= previous["seq"]:
            return None
        if self.clock() - previous["at"] < self.config.checkpoint_seconds:
            return None
        return self.checkpoint()

    # ------------------------------------------------------------------ reading

    def list_work(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.db.all("SELECT * FROM work_items ORDER BY updated_at DESC LIMIT ?", [limit])
        for row in rows:
            row["actions"] = ACTIONS.get(row["state"], ())
        return rows

    def detail(self, work_id: str) -> dict[str, Any] | None:
        work = self.work(work_id)
        if work is None:
            return None
        plans = self.db.all("SELECT * FROM plans WHERE work_id = ? ORDER BY version DESC", [work_id])
        for row in plans:
            row["plan"] = json.loads(row["plan"])
            row["errors"] = json.loads(row["errors"])
        runs = self.db.all("SELECT * FROM runs WHERE work_id = ? ORDER BY received_at DESC", [work_id])
        for row in runs:
            row["result"] = json.loads(row["result"])
        consults = self.db.all("SELECT * FROM consults WHERE work_id = ? ORDER BY id", [work_id])
        for row in consults:
            row["flags"] = json.loads(row["flags"])
        current = next((p for p in plans if p["version"] == work["current_version"]), None)
        previous = next((p for p in plans if p["version"] < work["current_version"] and not p["errors"]), None)
        return {
            "work": work,
            "continues": self.work(work["continues"]) if work["continues"] else None,
            "continued_by": self.db.all(
                "SELECT id, title, state, created_at FROM work_items WHERE continues = ? ORDER BY created_at", [work_id]
            ),
            "current": current,
            "changes": plan_diff(previous["plan"], current["plan"]) if current and previous else "",
            "previous_version": previous["version"] if current and previous else None,
            "plans": plans,
            "messages": self.db.all("SELECT * FROM messages WHERE work_id = ? ORDER BY id", [work_id]),
            "consults": consults,
            "approvals": self.db.all("SELECT * FROM approvals WHERE work_id = ? ORDER BY at DESC", [work_id]),
            "steps": self.db.all("SELECT * FROM run_steps WHERE work_id = ? ORDER BY id", [work_id]),
            "runs": runs,
            "ledger": self.ledger.entries(work_id=work_id),
        }

    # ------------------------------------------------------------------ loop

    async def tick(self) -> None:
        await self.dispatch_due()
        self.expire_investigations()
        self.expire_approvals()
        await self.launch_due()
        self.checkpoint_due()
        await self.outbox.deliver_due(self.client, now=self.clock())

    async def close_all(self) -> None:
        await self.client.aclose()
        self.db.close()


def plan_diff(before: Mapping[str, Any], after: Mapping[str, Any]) -> str:
    """What a revision changed, so reading version three means reading what is new in it."""
    old = json.dumps(before, indent=2, sort_keys=True, ensure_ascii=False).splitlines()
    new = json.dumps(after, indent=2, sort_keys=True, ensure_ascii=False).splitlines()
    return "\n".join(difflib.unified_diff(old, new, "before", "after", lineterm="", n=2))


def session_directive(hint: str) -> dict[str, str]:
    """What the investigator does with its engine session this round."""
    if hint == "fresh":
        return {"mode": "fresh"}
    if hint.startswith("fork:"):
        return {"mode": "fork", "from": hint[5:]}
    return {"mode": "resume"}
