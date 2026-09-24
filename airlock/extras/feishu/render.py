"""Cards: what each notification looks like in the chat. Markup is escaped here, where it is rendered.

Every text field arrives as plain facts from the outlet or the watcher, and
only this module knows which card slots render markup. ``lark_md`` does, so
payload text going into it is neutralised; the header and the note are
``plain_text``, which renders none. An alert titled ``<at id=all></at>`` once
paged a whole company through a renderer that did not know this.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

TONE = {"high": "red", "critical": "red", "medium": "orange", "low": "wathet", "info": "blue", "done": "green"}
RISK_TONE = {"high": "red", "medium": "orange", "low": "wathet"}
RUN_LABEL = {
    "run.finished": ("执行完成", "green"),
    "run.failed": ("执行失败", "red"),
    "run.refused": ("启动器拒绝执行", "red"),
    "run.cancelled": ("执行已急停", "orange"),
}
# A run the sandbox rule approved: nobody chose it, so the card says what is left to you.
RULE_RUN_LABEL = {
    "run.finished": ("沙箱跑完，待你审 diff", "green"),
    "run.failed": ("沙箱里没跑成", "red"),
    "run.refused": ("启动器拒绝了沙箱规则的批准", "red"),
    "run.cancelled": ("沙箱运行已急停", "orange"),
}
# The approver the core names when its sandbox rule approved (docs/security.md, 4b).
SANDBOX_RULE = "policy:sandbox"
_OPENERS = ("\\", "<", "[", "]")
# A report goes into the card's thread in pieces of this size: a phone cannot open a console on 127.0.0.1.
REPORT_EVENTS = ("work.answered", "plan.ready", "plan.revised")
CHUNK_CHARS = 2500
MAX_CHUNKS = 8
MAX_STEPS = 10
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


def escape(text: Any) -> str:
    out = str(text or "")
    for opener in _OPENERS:
        out = out.replace(opener, "\\" + opener)
    return out


def _md(content: str) -> dict[str, Any]:
    return {"tag": "div", "text": {"tag": "lark_md", "content": content}}


def _link_button(text: str, url: str) -> dict[str, Any] | None:
    if not str(url or "").startswith(("http://", "https://")):
        return None
    if urlparse(str(url)).hostname in _LOCAL_HOSTS:
        text += "（电脑上）"  # a console on this machine only: said on the button, not found out on a phone
    return {
        "tag": "action",
        "actions": [
            {"tag": "button", "text": {"tag": "plain_text", "content": text}, "type": "primary", "url": str(url)}
        ],
    }


def card(title: str, tone: str, blocks: list[str], *, link: str = "", link_text: str = "", note: str = "") -> dict:
    elements: list[dict[str, Any]] = [_md(block) for block in blocks if block]
    button = _link_button(link_text or "在控制台打开", link) if link else None
    if button:
        elements.append(button)
    if note:
        elements.append({"tag": "note", "elements": [{"tag": "plain_text", "content": note}]})
    return {
        "config": {"wide_screen_mode": True},
        "header": {"title": {"tag": "plain_text", "content": title[:120]}, "template": tone},
        "elements": elements,
    }


REPLY_HINT = "在这张卡片下回复并 @ 机器人：调查员会按你的话接着查或修订方案（新版本要重新批准）。批准只在控制台。"
IN_THREAD = "报告全文在这张卡片的话题里。"


def _steps(payload: dict[str, Any]) -> str:
    """The plan's steps, one line each, so a phone shows what would run."""
    steps = [s for s in payload.get("steps") or [] if isinstance(s, dict)]
    if not steps:
        return ""
    lines = [
        f"{i}. {escape(s.get('worker'))} · {escape(s.get('target'))}：{escape(s.get('what'))}"
        for i, s in enumerate(steps[:MAX_STEPS], start=1)
    ]
    if len(steps) > MAX_STEPS:
        lines.append(f"……还有 {len(steps) - MAX_STEPS} 步")
    return "**步骤**\n" + "\n".join(lines)


def _chunks(text: str, size: int) -> list[str]:
    """Pieces of at most ``size`` characters, cut between paragraphs where it can be and between lines otherwise."""
    pieces: list[str] = []
    current = ""
    for paragraph in re.split(r"\n\s*\n", text):
        for part in [paragraph[i : i + size] for i in range(0, len(paragraph), size)] or [""]:
            joined = f"{current}\n\n{part}" if current else part
            if len(joined) <= size:
                current = joined
                continue
            if current:
                pieces.append(current)
            current = part
    if current.strip():
        pieces.append(current)
    return pieces


def report_cards(event: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    """The whole report, as cards for the thread under the event's card. Nothing when the lead already says it all."""
    if event not in REPORT_EVENTS:
        return []
    text = str(payload.get("report") or "").strip()
    without_headings = re.sub(r"^#{1,6}\s+.*$", "", text, flags=re.M).strip()
    if not text or without_headings == str(payload.get("lead") or "").strip():
        return []
    # lark_md has no headings: a heading line becomes a bold one. Everything is escaped like every other field.
    text = re.sub(r"^#{1,6}\s+(.+?)\s*#*$", r"**\1**", text, flags=re.M)
    chunks = _chunks(text, CHUNK_CHARS)
    cut = bool(payload.get("report_truncated")) or len(chunks) > MAX_CHUNKS
    chunks = chunks[:MAX_CHUNKS]
    title = str(payload.get("title") or "工作项")
    cards = []
    for index, chunk in enumerate(chunks, start=1):
        numbered = f" {index}/{len(chunks)}" if len(chunks) > 1 else ""
        last = index == len(chunks)
        note = "报告太长，后面没有发，全文在控制台（电脑上）。" if cut and last else ""
        cards.append(card(f"报告全文{numbered}：{title}", "grey", [escape(chunk)], note=note))
    return cards


def for_event(event: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    """The card for one outlet notification, or None for events that do not need one."""
    title = str(payload.get("title") or "工作项")
    link = str(payload.get("link") or "")
    work = f"工作项 {payload.get('work_id', '')}"
    in_thread = IN_THREAD if report_cards(event, payload) else ""
    if event in ("plan.ready", "plan.revised"):
        version = payload.get("version")
        risk = str(payload.get("risk") or "")
        if payload.get("approved_by") == SANDBOX_RULE:
            blocks = [
                escape(payload.get("lead")),
                f"**方案**：{escape(payload.get('summary'))}",
                _steps(payload),
                "由沙箱规则批准，已经开始跑：只在一份没有 remote 的新克隆里改，除了模型拿不到任何凭证。"
                "跑完会发改动，diff 在控制台审，用不用由你决定。",
                in_thread,
            ]
            return card(
                f"沙箱里自动执行 v{version}：{title}",
                "wathet",
                blocks,
                link=link,
                link_text="看方案",
                note=f"{work} · 在这张卡片下回复并 @ 机器人：调查员会按你的话接着查或修订方案。",
            )
        head = "方案已修订" if event == "plan.revised" else "方案待批准"
        allowance = payload.get("allowance") or {}
        why_yours = {
            "allowance": f"沙箱工作画像 {escape(allowance.get('worker'))} 过去 24 小时已由规则批准 "
            f"{escape(allowance.get('used'))} 次（上限 {escape(allowance.get('limit'))}），这一版等你批准。",
            "approved_once": "这一版沙箱规则已经批准过一次；要再跑一遍，在控制台批准。",
        }
        blocks = [
            escape(payload.get("lead")),
            f"**方案**：{escape(payload.get('summary'))}",
            f"**风险**：{escape(risk or '未标注')}　**版本**：v{escape(version)}",
            _steps(payload),
            "相对上一版有改动，批准前看一下差异。" if payload.get("changed") else "",
            why_yours.get(str(payload.get("rule_declined") or ""), ""),
            in_thread,
        ]
        return card(
            f"{head} v{version}：{title}",
            RISK_TONE.get(risk, "orange"),
            blocks,
            link=link,
            link_text="看方案并批准",
            note=f"{work} · {REPLY_HINT}",
        )
    if event == "work.answered":
        return card(
            f"调查完成：{title}",
            "blue",
            [
                escape(payload.get("lead") or payload.get("summary") or "调查员给出了结论，没有需要执行的方案。"),
                in_thread,
            ],
            link=link,
            link_text="看报告",
            note=f"{work} · {REPLY_HINT}",
        )
    if event in ("work.error", "plan.invalid"):
        why = payload.get("reason") or "; ".join(str(e) for e in payload.get("errors") or []) or "见控制台"
        head = "方案没通过校验" if event == "plan.invalid" else "调查出错"
        return card(f"{head}：{title}", "red", [escape(why)[:1500]], link=link, note=work)
    if event in RUN_LABEL:
        ruled = payload.get("approved_by") == SANDBOX_RULE
        label, tone = (RULE_RUN_LABEL if ruled else RUN_LABEL)[event]
        lines = []
        for index, group in enumerate(payload.get("groups") or [], start=1):
            line = f"第 {index} 组 {escape(group.get('worker'))}：{escape(group.get('status'))}"
            workspace = group.get("workspace") or {}
            if workspace.get("repo"):
                line += (
                    f"；改了 {escape(workspace.get('repo'))} 的 {workspace.get('files_changed', 0)} 个文件，"
                    f"+{workspace.get('insertions', 0)} −{workspace.get('deletions', 0)}"
                )
            lines.append(line)
        reason = payload.get("reason")
        blocks = ["\n".join(lines), f"原因：{escape(reason)}" if reason else ""]
        link_text = "审 diff" if ruled and event == "run.finished" else "看执行记录"
        return card(f"{label}：{title}", tone, blocks, link=link, link_text=link_text, note=work)
    if event in ("approval.expired", "approval.revoked"):
        what = "批准已过期，没有执行" if event == "approval.expired" else "批准已撤回"
        return card(f"{what}：{title}", "grey", [], link=link, note=work)
    return None


def for_notice(notice: dict[str, Any]) -> dict[str, Any]:
    """A watcher's signal. A task says it went to an investigator; a note is only to read."""
    level, kind = str(notice.get("level") or "low"), str(notice.get("kind") or "note")
    head = "交给调查员：" if kind == "task" else ""
    blocks = [escape(notice.get("detail")), f"来源：{escape(notice.get('origin'))}"]
    note = "回复这张卡片并 @ 机器人，就开一个新的工作项。" if kind == "note" else "调查结果会发到方案群。"
    return card(
        f"{head}{notice.get('title') or '盯守'}",
        TONE.get(level, "wathet"),
        blocks,
        link=str(notice.get("link") or ""),
        link_text="在控制台打开",
        note=note,
    )
