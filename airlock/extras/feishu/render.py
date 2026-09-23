"""Cards: what each notification looks like in the chat. Markup is escaped here, where it is rendered.

Every text field arrives as plain facts from the outlet or the watcher, and
only this module knows which card slots render markup. ``lark_md`` does, so
payload text going into it is neutralised; the header and the note are
``plain_text``, which renders none. An alert titled ``<at id=all></at>`` once
paged a whole company through a renderer that did not know this.
"""

from __future__ import annotations

from typing import Any

TONE = {"high": "red", "critical": "red", "medium": "orange", "low": "wathet", "info": "blue", "done": "green"}
RISK_TONE = {"high": "red", "medium": "orange", "low": "wathet"}
RUN_LABEL = {
    "run.finished": ("执行完成", "green"),
    "run.failed": ("执行失败", "red"),
    "run.refused": ("启动器拒绝执行", "red"),
    "run.cancelled": ("执行已急停", "orange"),
}
_OPENERS = ("\\", "<", "[", "]")


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


def for_event(event: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    """The card for one outlet notification, or None for events that do not need one."""
    title = str(payload.get("title") or "工作项")
    link = str(payload.get("link") or "")
    work = f"工作项 {payload.get('work_id', '')}"
    if event in ("plan.ready", "plan.revised"):
        version = payload.get("version")
        risk = str(payload.get("risk") or "")
        head = "方案已修订" if event == "plan.revised" else "方案待批准"
        blocks = [
            escape(payload.get("lead")),
            f"**方案**：{escape(payload.get('summary'))}",
            f"**风险**：{escape(risk or '未标注')}　**版本**：v{escape(version)}",
            "相对上一版有改动，批准前看一下差异。" if payload.get("changed") else "",
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
            [escape(payload.get("lead") or payload.get("summary") or "调查员给出了结论，没有需要执行的方案。")],
            link=link,
            link_text="看报告",
            note=f"{work} · {REPLY_HINT}",
        )
    if event in ("work.error", "plan.invalid"):
        why = payload.get("reason") or "; ".join(str(e) for e in payload.get("errors") or []) or "见控制台"
        head = "方案没通过校验" if event == "plan.invalid" else "调查出错"
        return card(f"{head}：{title}", "red", [escape(why)[:1500]], link=link, note=work)
    if event in RUN_LABEL:
        label, tone = RUN_LABEL[event]
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
        return card(f"{label}：{title}", tone, blocks, link=link, link_text="看执行记录", note=work)
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
