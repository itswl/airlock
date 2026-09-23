"""Mirrors of the repositories investigators read and workers change, kept at their remote's latest commit.

    python -m airlock.extras.mirrors --config mirrors.yaml [--once]

An investigator answering "how would this be done" against a checkout from
last month answers for last month; the planner this replaces said so itself, eight times.
So each repository named here is cloned once into ``root/<name>`` and then
fetched and reset to its remote branch on every tick. The investigators mount
``root`` read-only. A worker with ``repos`` clones from it for every run and
never writes it (airlock.launcher.workspace).

The token is read-only, and it never appears on a command line. git asks a
credential helper, and the helper reads the token from the environment of the
git process.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from airlock.extras.settings import SettingsError, value
from airlock.extras.watch.scan import write_atomically

logger = logging.getLogger("airlock.mirrors")
_HELPER = '!f() { echo "username=${AIRLOCK_MIRRORS_USER}"; echo "password=${AIRLOCK_MIRRORS_PASSWORD}"; }; f'


@dataclass(frozen=True)
class Repo:
    name: str
    url: str
    branch: str = ""


@dataclass(frozen=True)
class MirrorsConfig:
    root: Path
    repos: tuple[Repo, ...]
    every_minutes: int
    username: str
    token: str


def load_mirrors(source: str | Path | Mapping[str, Any], env: Mapping[str, str] | None = None) -> MirrorsConfig:
    env = os.environ if env is None else env
    data = source if isinstance(source, Mapping) else yaml.safe_load(Path(source).read_text(encoding="utf-8"))
    repos = []
    for item in data.get("repos") or []:
        name = str(item.get("name") or "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name) or not item.get("url"):
            raise SettingsError(f"mirrors: each repo has a name (letters, digits, . - _) and a url: {item}")
        repos.append(Repo(name, str(item["url"]), str(item.get("branch") or "")))
    if not repos:
        raise SettingsError("mirrors: no repos")
    return MirrorsConfig(
        root=Path(str(data.get("root") or "repos")),
        repos=tuple(repos),
        every_minutes=int(data.get("every_minutes") or 15),
        username=str(data.get("username") or "x-access-token"),
        token=value(data, "token", env, "mirrors"),
    )


def _git(config: MirrorsConfig, *argv: str, cwd: Path | None = None) -> str:
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "AIRLOCK_MIRRORS_USER": config.username,
        "AIRLOCK_MIRRORS_PASSWORD": config.token,
    }
    command = ["git", "-c", "credential.helper=", "-c", f"credential.helper={_HELPER}", *argv]
    done = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=600, check=False)  # noqa: S603
    if done.returncode != 0:
        raise RuntimeError((done.stderr or done.stdout).strip()[-300:] or f"git {argv[0]} failed")
    return done.stdout.strip()


def sync(config: MirrorsConfig, repo: Repo) -> dict[str, Any]:
    path = config.root / repo.name
    started = time.time()
    try:
        if not (path / ".git").exists():
            config.root.mkdir(parents=True, exist_ok=True)
            _git(config, "clone", "--quiet", repo.url, str(path))
        _git(config, "fetch", "--quiet", "--prune", "origin", cwd=path)
        branch = repo.branch or _git(config, "rev-parse", "--abbrev-ref", "origin/HEAD", cwd=path).split("/", 1)[-1]
        # The mirror is nobody's working copy: whatever is there is replaced by the remote's branch.
        _git(config, "checkout", "--quiet", "--force", "-B", branch, f"origin/{branch}", cwd=path)
        _git(config, "clean", "-fdxq", cwd=path)
        head = _git(config, "rev-parse", "HEAD", cwd=path)
        return {"ok": True, "head": head, "branch": branch, "at": started}
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        message = str(exc).replace(config.token, "[token]") if config.token else str(exc)
        return {"ok": False, "error": message[:300], "at": started}


def sync_all(config: MirrorsConfig) -> dict[str, dict[str, Any]]:
    results = {repo.name: sync(config, repo) for repo in config.repos}
    write_atomically(config.root / ".mirrors-status.json", {"at": time.time(), "repos": results})
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m airlock.extras.mirrors", description=__doc__.splitlines()[0])
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        config = load_mirrors(args.config)
    except (SettingsError, OSError) as exc:
        print(f"mirrors: {exc}", file=sys.stderr)
        return 2
    while True:
        for name, result in sync_all(config).items():
            logger.info("%s: %s", name, result.get("head", "")[:12] if result["ok"] else f"FAILED {result['error']}")
        if args.once:
            return 0
        time.sleep(config.every_minutes * 60)


if __name__ == "__main__":
    sys.exit(main())
