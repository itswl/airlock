"""What the launcher checks for itself before it runs a plan the sandbox rule approved.

The rule (``approval: sandbox`` on a worker profile, docs/security.md 4b) lets
a plan run without your click when every step is on a worker whose container
can reach nothing but a fresh clone and its model. What a profile can show is
checked when the configuration loads: it has ``repos`` and no fixed workspace,
its environment names only a proxy and a locale. What a profile cannot show
about itself is checked here, where the directories and the networks are:

* its credentials directory holds ``engine.env`` and nothing else, and
  ``engine.env`` sets model settings and nothing else, so the only key in the
  container is the model's;
* its network is ``none`` or an internal Docker network, so what it reaches
  beyond the containers on that network is what the egress proxy lets through
  (the runtime inspects this when the launcher starts);
* it runs in a container at all: a launcher on the local runtime isolates
  nothing, and runs nothing on the rule's word.

Your own approvals are not checked here: what they may do is still exactly the
profile's allowlist and permissions.
"""

from __future__ import annotations

import re
from pathlib import Path

from airlock.runner.executor import ENGINE_ENV, engine_env

# What a task-mode engine reads from engine.env. Anything else there could be a key to something else.
MODEL_SETTING = re.compile(r"(ANTHROPIC|CLAUDE_CODE)_[A-Z0-9_]+|AIRLOCK_MODEL|API_TIMEOUT_MS|DISABLE_[A-Z0-9_]+")


def credentials_problem(credentials_dir: str | None) -> str | None:
    """Why this worker's credentials directory holds more than its model's settings, or None."""
    if not credentials_dir:
        return None
    root = Path(credentials_dir)
    try:
        names = sorted(entry.name for entry in root.iterdir())
    except OSError as exc:
        return f"its credentials directory cannot be read ({type(exc).__name__})"
    extra = [name for name in names if name != ENGINE_ENV]
    if extra:
        shown = ", ".join(extra[:5]) + (", …" if len(extra) > 5 else "")
        return f"its credentials directory holds {shown} besides {ENGINE_ENV}"
    path = root / ENGINE_ENV
    if path.is_symlink() or (names and not path.is_file()):
        return f"its {ENGINE_ENV} is not a plain file"
    other = sorted(key for key in engine_env(str(root)) if not MODEL_SETTING.fullmatch(key))
    if other:
        return f"its {ENGINE_ENV} sets {', '.join(other[:5])}, which is not a model setting"
    return None
