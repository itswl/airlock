"""What an investigator wants remembered: proposed in its report, accepted by you, written by the control plane.

A profile's memory is a file its investigator reads at the start of every run,
after its instructions. Investigations keep learning things that belong there
("the staging database is restored every Sunday at 03:00"), and the only way
such a fact used to survive a run was somebody noticing it and typing it in.

So a report may end with lines ``MEMORY-SUGGESTION: <one fact>``. The control
plane lifts them out of the report (the chat does not need them), queues them,
and the console offers accept or dismiss. Accepted facts are appended to
``<data dir>/memory/<profile>.md``, which the investigator mounts read-only.
The investigator never writes its own memory. A run steered by an injected
message can stuff the queue with nonsense that you dismiss. It cannot put
one line into what the next run believes.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

PREFIX = "MEMORY-SUGGESTION:"
MAX_PER_REPORT = 5
MAX_CHARS = 300
MAX_FILE_BYTES = 16_000
_LINE = re.compile(r"^\s*MEMORY-SUGGESTION:\s*(.+?)\s*$", re.M)
HEADER = "# 记住的事实\n\n由调查员提议、操作员在控制台确认后写入。每次调查开始时读一遍。\n"


def lift(text: str) -> tuple[str, list[str]]:
    """The report without its suggestion lines, and the suggestions (at most five, one line each)."""
    found = [m.group(1)[:MAX_CHARS] for m in _LINE.finditer(text or "")][:MAX_PER_REPORT]
    return _LINE.sub("", text or "").rstrip() + ("\n" if text and text.endswith("\n") else ""), found


def path_for(data_dir: Path, profile: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", profile):
        raise ValueError(f"profile name {profile!r} cannot name a memory file")
    return data_dir / "memory" / f"{profile}.md"


def append(path: Path, fact: str, *, work_id: str, at: float | None = None) -> None:
    """One accepted fact, with when and from which work item, at the end of the profile's memory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d", time.localtime(time.time() if at is None else at))
    current = path.read_text(encoding="utf-8") if path.exists() else HEADER
    line = f"- {fact.strip()}（{stamp}，工作项 {work_id}）\n"
    if len((current + line).encode("utf-8")) > MAX_FILE_BYTES:
        raise ValueError(f"the memory file would pass {MAX_FILE_BYTES} bytes; edit it down before adding more")
    path.write_text(current.rstrip("\n") + "\n" + line, encoding="utf-8")
    path.chmod(0o644)  # read by the investigator's uid through a read-only mount


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")[:MAX_FILE_BYTES]
    except OSError:
        return ""
