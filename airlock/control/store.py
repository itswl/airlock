"""The control plane's tables. One SQLite file; the ledger lives beside them."""

from __future__ import annotations

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    source TEXT NOT NULL,
    received_at REAL NOT NULL,
    outcome TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    key TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    work_id TEXT,
    body_digest TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS work_items (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    source TEXT NOT NULL,
    key TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    labels TEXT NOT NULL DEFAULT '[]',
    fields TEXT NOT NULL DEFAULT '{}',
    investigator TEXT NOT NULL,
    state TEXT NOT NULL,
    current_version INTEGER NOT NULL DEFAULT 0,
    dispatch_attempts INTEGER NOT NULL DEFAULT 0,
    next_dispatch_at REAL NOT NULL DEFAULT 0,
    auto_revisions INTEGER NOT NULL DEFAULT 0,
    last_seen_message INTEGER NOT NULL DEFAULT 0,
    dispatched_at REAL NOT NULL DEFAULT 0,
    last_signal_at REAL NOT NULL DEFAULT 0,
    signals INTEGER NOT NULL DEFAULT 1,
    concluded_at REAL,
    continues TEXT,
    session_hint TEXT NOT NULL DEFAULT '',
    engine_session TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS work_state ON work_items(state, next_dispatch_at);
CREATE INDEX IF NOT EXISTS work_key ON work_items(source, key, last_signal_at);
CREATE TABLE IF NOT EXISTS plans (
    work_id TEXT NOT NULL REFERENCES work_items(id),
    version INTEGER NOT NULL,
    created_at REAL NOT NULL,
    author TEXT NOT NULL,
    plan TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    errors TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (work_id, version)
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    work_id TEXT NOT NULL REFERENCES work_items(id),
    at REAL NOT NULL,
    author TEXT NOT NULL,
    via TEXT NOT NULL DEFAULT 'web',
    text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS consults (
    id INTEGER PRIMARY KEY,
    work_id TEXT NOT NULL REFERENCES work_items(id),
    at REAL NOT NULL,
    from_profile TEXT NOT NULL,
    to_profile TEXT NOT NULL,
    question TEXT NOT NULL,
    answer TEXT,
    answered_at REAL,
    status TEXT NOT NULL,
    flags TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    work_id TEXT NOT NULL REFERENCES work_items(id),
    version INTEGER NOT NULL,
    plan_hash TEXT NOT NULL,
    approver TEXT NOT NULL,
    via TEXT NOT NULL,
    at REAL NOT NULL,
    expires_at REAL NOT NULL,
    status TEXT NOT NULL,
    launch_attempts INTEGER NOT NULL DEFAULT 0,
    next_launch_at REAL NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS runs (
    approval_id TEXT PRIMARY KEY REFERENCES approvals(id),
    work_id TEXT NOT NULL REFERENCES work_items(id),
    received_at REAL NOT NULL,
    status TEXT NOT NULL,
    result TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS run_steps (
    id INTEGER PRIMARY KEY,
    approval_id TEXT NOT NULL REFERENCES approvals(id),
    work_id TEXT NOT NULL REFERENCES work_items(id),
    at REAL NOT NULL,
    group_index INTEGER NOT NULL,
    worker TEXT NOT NULL,
    event TEXT NOT NULL,
    step_index INTEGER,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '',
    exit_code INTEGER,
    duration_ms INTEGER,
    tail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS run_steps_work ON run_steps(work_id, id);
CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY,
    created_at REAL NOT NULL,
    subscription TEXT NOT NULL,
    event TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_at REAL NOT NULL,
    last_error TEXT NOT NULL DEFAULT '',
    sent_at REAL
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(status, next_at);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- What you said about a work item's result: the latest rating (every rating is also in the ledger).
CREATE TABLE IF NOT EXISTS ratings (
    work_id TEXT PRIMARY KEY REFERENCES work_items(id),
    rating TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    via TEXT NOT NULL,
    at REAL NOT NULL
);
-- Facts an investigator proposed remembering (airlock.control.memory); you accept or dismiss each.
CREATE TABLE IF NOT EXISTS suggestions (
    id INTEGER PRIMARY KEY,
    profile TEXT NOT NULL,
    work_id TEXT NOT NULL REFERENCES work_items(id),
    at REAL NOT NULL,
    text TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    decided_at REAL
);
"""

# A work item in one of these is finished. A new signal with the same key after
# that is new work, not an update to the old one. Finished is not frozen: a
# message from you re-opens any of them for another round of investigation.
TERMINAL = ("done", "failed", "refused", "cancelled", "rejected", "closed", "error", "plan_invalid")

# What you can do next, by state. The web page and the adapters both read this,
# so a button that is shown is a button that works.
ACTIONS: dict[str, tuple[str, ...]] = {
    "queued": ("message", "close"),
    "investigating": ("message", "close"),
    "answered": ("message", "fresh", "close"),
    "plan_ready": ("approve", "message", "fresh", "reject"),
    "approved": ("revoke", "message"),
    "running": ("cancel", "message"),
    "plan_invalid": ("message", "fresh", "close"),
    "error": ("message", "fresh", "close"),
    "failed": ("message", "fresh"),
    "refused": ("message", "fresh"),
    "cancelled": ("message", "fresh"),
    "done": ("message", "fresh"),
    "rejected": ("message", "fresh"),
    "closed": ("message", "fresh"),
}

# A work item in one of these has concluded: the investigation answered, or
# what came of its plan is known. A repeat of its signal soon after continues
# its investigator's session in a new work item. Not after an error or a plan
# that never validated: that session is not one worth building on.
CONCLUDED = ("answered", "done", "failed", "refused", "cancelled", "rejected", "closed")

# A message from you in one of these sends the work item back to its
# investigator. In the others it is recorded and read on the next round.
REOPENS = (
    "answered",
    "plan_ready",
    "plan_invalid",
    "error",
    "failed",
    "refused",
    "cancelled",
    "done",
    "rejected",
    "closed",
)
