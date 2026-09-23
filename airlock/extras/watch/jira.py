"""The ticket part of the scan: what changed in one Jira project, and in issues assigned to you or mentioning you.

New issues, status and assignee changes, edits, and comments — skipping your
own. Each issue remembers the newest change already reported, so a lookback
window that overlaps the last one (it does, on purpose: a round that crashed
must be covered by the next) never reports the same change twice.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

import httpx

from airlock.extras.watch.config import JiraSource

OVERLAP_SECONDS = 120
REPORTED_TTL_SECONDS = 7 * 86400
FIELDS_WATCHED = ("status", "assignee", "summary", "duedate", "priority", "description")

Fetch = Callable[[str, dict[str, str]], dict[str, Any]]


def http_fetch(source: JiraSource, transport: httpx.BaseTransport | None = None) -> Fetch:
    auth = base64.b64encode(f"{source.email}:{source.token}".encode()).decode()
    client = httpx.Client(
        base_url=source.site,
        timeout=30.0,
        transport=transport,
        headers={"Authorization": f"Basic {auth}", "Accept": "application/json"},
    )

    def fetch(path: str, params: dict[str, str]) -> dict[str, Any]:
        response = client.get(path, params=params)
        response.raise_for_status()
        return response.json()

    return fetch


def _ts(iso: str) -> float:
    return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def adf_text(node: Any) -> str:
    """Plain text out of Atlassian's document format."""
    out: list[str] = []
    if isinstance(node, dict):
        if node.get("type") == "text":
            out.append(str(node.get("text") or ""))
        if node.get("type") == "hardBreak":
            out.append(" ")
        for child in node.get("content") or []:
            out.append(adf_text(child))
        if node.get("type") in ("paragraph", "heading", "listItem"):
            out.append(" ")
    elif isinstance(node, list):
        out.extend(adf_text(child) for child in node)
    return "".join(out)


def scan_jira(source: JiraSource, state: dict[str, Any], fetch: Fetch, now: float | None = None) -> list[str]:
    """Lines for the digest (empty when nothing changed). Updates ``state`` in place."""
    now = time.time() if now is None else now
    last = float(state.get("last_check") or now - 6 * 3600)
    cutoff = min(last - OVERLAP_SECONDS, now - source.lookback_minutes * 60)
    reported: dict[str, float] = dict(state.get("reported") or {})
    me = state.get("my_account_id")
    if not me:
        me = fetch("/rest/api/3/myself", {})["accountId"]
        state["my_account_id"] = me
    # JQL dates are read in the Jira account's own zone; minutes are enough.
    zone = ZoneInfo(source.tz) if source.tz else None
    since = datetime.fromtimestamp(cutoff, zone).strftime("%Y-%m-%d %H:%M")
    scope = f"project = {source.project} OR assignee = currentUser()"
    if source.mention:
        scope += f' OR comment ~ "{source.mention}"'
    jql = f'({scope}) AND updated >= "{since}" ORDER BY updated ASC'
    try:
        hits = fetch("/rest/api/3/search/jql", {"jql": jql, "fields": "summary,status,updated", "maxResults": "30"})
    except httpx.HTTPError:
        if not source.mention:
            raise
        # `comment ~` needs an index the account may not have.
        plain = (
            f'(project = {source.project} OR assignee = currentUser()) AND updated >= "{since}" ORDER BY updated ASC'
        )
        hits = fetch("/rest/api/3/search/jql", {"jql": plain, "fields": "summary,status,updated", "maxResults": "30"})
    lines: list[str] = []
    for hit in hits.get("issues") or []:
        key = str(hit["key"])
        issue = fetch(
            f"/rest/api/3/issue/{key}",
            {"fields": "summary,status,assignee,reporter,created,comment", "expand": "changelog"},
        )
        fields = issue["fields"]
        seen = reported.get(key)
        floor = max(cutoff, float(seen or 0))
        newest = floor

        def is_new(at: float, floor: float = floor, seen: Any = seen) -> bool:
            # Strictly after what was already reported: the newest change reported last
            # round has exactly that timestamp, and ">=" would report it every round.
            return at > floor if seen is not None and float(seen) >= cutoff else at >= floor

        changes: list[str] = []
        if is_new(_ts(fields["created"])) and (fields.get("reporter") or {}).get("accountId") != me:
            assignee = (fields.get("assignee") or {}).get("displayName", "未分配")
            changes.append(f"🆕 新建 by {fields['reporter']['displayName']}，处理人 {assignee}")
        for history in (issue.get("changelog") or {}).get("histories") or []:
            at = _ts(history["created"])
            if not is_new(at) or history["author"].get("accountId") == me:
                continue
            newest = max(newest, at)
            for item in history.get("items") or []:
                if item.get("field") not in FIELDS_WATCHED:
                    continue
                if item["field"] == "description":
                    changes.append(f"✏️ {history['author']['displayName']} 改了描述")
                else:
                    before, after = item.get("fromString") or "-", item.get("toString") or "-"
                    changes.append(f"🔀 {history['author']['displayName']}: {item['field']} {before} → {after}")
        for comment in (fields.get("comment") or {}).get("comments") or []:
            at = max(_ts(comment["created"]), _ts(comment.get("updated", comment["created"])))
            if is_new(at) and comment["author"].get("accountId") != me:
                newest = max(newest, at)
                excerpt = adf_text(comment.get("body") or {}).strip()[:200]
                changes.append(f"💬 {comment['author']['displayName']}: {excerpt}")
        if changes:
            lines.append(f"{key} [{fields['status']['name']}] {fields['summary']}")
            lines += [f"  {change}" for change in changes]
            reported[key] = max(newest, floor)
    state["last_check"] = now
    state["reported"] = {k: v for k, v in reported.items() if v > now - REPORTED_TTL_SECONDS}
    return lines
