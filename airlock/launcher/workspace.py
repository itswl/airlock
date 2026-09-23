"""A repository a worker may change: a fresh clone for every run, and the change kept outside the container.

A worker profile names the repositories it may change (``repos``: name → a
local git repository, usually a mirror the operator keeps up to date). Every
run gets its own clone of the named repository, made by the launcher before the
container starts, with no remote: nothing a worker commits can reach the
mirror, a push has nowhere to go, and the next run starts clean.

When the group ends, the launcher records what changed. It does that WITHOUT
running git in the workspace. The worker owned that directory for the whole
run, including ``.git/config`` and ``.gitattributes``, and git executes
programs named there (``core.fsmonitor``, filter and diff drivers). A launcher
that ran ``git diff`` in it would be running the worker's code, outside the
container, next to the Docker socket. So the start of the change is read from
the mirror at the commit the clone began from (the operator's repository,
trusted), the end is read from the workspace as plain files (``.git`` skipped,
symbolic links recorded as links and never followed, special files skipped),
and the difference is computed here. File modes are not compared.
"""

from __future__ import annotations

import difflib
import io
import os
import re
import stat
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from airlock.crypto import sha256_hex

REPO_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
TARGET_PREFIX = "repo:"
MAX_FILES = 100_000
MAX_FILE_BYTES = 1_000_000
MAX_PATCH_BYTES = 2_000_000
_GIT_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"}


class WorkspaceError(RuntimeError):
    """The workspace could not be prepared. The message says why."""


def repo_of(target: str) -> str | None:
    """The repository a step's target names (``repo:<name>``), or None."""
    if not target.startswith(TARGET_PREFIX):
        return None
    name = target[len(TARGET_PREFIX) :]
    return name if REPO_NAME.fullmatch(name) else None


def _git(*argv: str, cwd: Path | None = None, trusted: Path | None = None) -> bytes:
    """git on a repository the launcher trusts: the operator's mirror, or a clone it just made."""
    command = ["git"]
    if trusted is not None:
        # The mirror may belong to another user than the launcher; it is the
        # operator's own repository, which is what safe.directory is for.
        command += ["-c", f"safe.directory={trusted}"]
    command += list(argv)
    done = subprocess.run(  # noqa: S603 — fixed git subcommands, no shell
        command,
        cwd=cwd,
        capture_output=True,
        env={**os.environ, **_GIT_ENV},
        timeout=300,
        check=False,
    )
    if done.returncode != 0:
        raise WorkspaceError(f"git {argv[0]} failed: {done.stderr.decode('utf-8', 'replace').strip()[-400:]}")
    return done.stdout


@dataclass(frozen=True)
class Prepared:
    repo: str
    source: Path
    path: Path
    start: str


def prepare(repo: str, source: Path, dest: Path) -> Prepared:
    """A fresh clone of ``source`` at ``dest``, with no remote. ``dest`` must not exist yet."""
    source = source.resolve()
    if dest.exists():
        raise WorkspaceError(f"{dest} already exists; a workspace is made once per run")
    dest.parent.mkdir(parents=True, exist_ok=True)
    _git("clone", "--quiet", "--no-hardlinks", str(source), str(dest), trusted=source)
    _git("remote", "remove", "origin", cwd=dest)
    start = _git("rev-parse", "HEAD", cwd=dest).decode().strip()
    return Prepared(repo=repo, source=source, path=dest, start=start)


def _tree_at(source: Path, commit: str) -> dict[str, tuple[str, bytes]]:
    """Every file of the mirror at ``commit``: path → (kind, content). Read from the mirror, never the workspace."""
    archive = _git("archive", "--format=tar", commit, cwd=source, trusted=source)
    files: dict[str, tuple[str, bytes]] = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            if member.issym():
                files[member.name] = ("link", member.linkname.encode())
            elif member.isfile():
                handle = tar.extractfile(member)
                files[member.name] = ("file", handle.read() if handle else b"")
    return files


def _tree_of(path: Path) -> tuple[dict[str, tuple[str, bytes]], bool]:
    """The workspace as plain files: ``.git`` skipped, links recorded as links, nothing followed."""
    files: dict[str, tuple[str, bytes]] = {}
    for root, dirs, names in os.walk(path, followlinks=False):
        rel_root = os.path.relpath(root, path)
        if rel_root == ".":
            dirs[:] = [d for d in dirs if d != ".git"]
        for name in sorted(names) + [d for d in dirs if os.path.islink(os.path.join(root, d))]:
            full = os.path.join(root, name)
            rel = name if rel_root == "." else f"{rel_root}/{name}"
            if len(files) >= MAX_FILES:
                return files, True
            info = os.lstat(full)
            if stat.S_ISLNK(info.st_mode):
                files[rel] = ("link", os.readlink(full).encode())
            elif stat.S_ISREG(info.st_mode):
                if info.st_size > MAX_FILE_BYTES:
                    files[rel] = ("large", f"{info.st_size} bytes".encode())
                else:
                    # O_NOFOLLOW as well as the lstat above: a link is recorded as a link, never read through.
                    fd = os.open(full, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                    with os.fdopen(fd, "rb") as handle:
                        files[rel] = ("file", handle.read())
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
    return files, False


def _text(content: bytes) -> list[str] | None:
    if b"\x00" in content:
        return None
    try:
        return content.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        return None


def _file_diff(path: str, before: tuple[str, bytes] | None, after: tuple[str, bytes] | None) -> str:
    """One file's change in git's patch format, so ``git apply`` takes it for text files."""
    header = f"diff --git a/{path} b/{path}\n"
    if {side[0] for side in (before, after) if side is not None} - {"file"}:
        return header + _describe(path, before, after)
    old_name = f"a/{path}" if before else "/dev/null"
    new_name = f"b/{path}" if after else "/dev/null"
    old_lines = _text(before[1]) if before else []
    new_lines = _text(after[1]) if after else []
    if old_lines is None or new_lines is None:
        return header + f"Binary files {old_name} and {new_name} differ\n"
    if before is None:
        header += "new file mode 100644\n"
    elif after is None:
        header += "deleted file mode 100644\n"
    lines = difflib.unified_diff(old_lines, new_lines, fromfile=old_name, tofile=new_name)
    return header + "".join(
        line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in lines
    )


def _describe(path: str, before: tuple[str, bytes] | None, after: tuple[str, bytes] | None) -> str:
    """A change git's unified diff cannot carry as text: a link, or a file too large to compare."""

    def one(side: tuple[str, bytes] | None) -> str:
        if side is None:
            return "absent"
        kind, content = side
        if kind == "link":
            return f"symbolic link to {content.decode('utf-8', 'replace')}"
        if kind == "large":
            return f"file of {content.decode()} (not compared)"
        return f"file of {len(content)} bytes"

    return f"# {path}: {one(before)} -> {one(after)}\n"


def changes(prepared: Prepared, patch_path: Path) -> dict[str, Any]:
    """What the run changed, as the tree's end state against the commit the clone started from."""
    before = _tree_at(prepared.source, prepared.start)
    after, cut = _tree_of(prepared.path)
    notes: list[str] = []
    paths = set(after) if cut else set(before) | set(after)
    if cut:
        notes.append(f"more than {MAX_FILES} files: only those read were compared, and no deletion was looked for")
    changed = sorted(p for p in paths if before.get(p) != after.get(p))
    parts, insertions, deletions = [], 0, 0
    for path in changed:
        part = _file_diff(path, before.get(path), after.get(path))
        parts.append(part)
        in_hunk = False
        for line in part.splitlines():
            if line.startswith("@@"):
                in_hunk = True
            elif in_hunk and line.startswith("+"):
                insertions += 1
            elif in_hunk and line.startswith("-"):
                deletions += 1
    raw = "".join(parts).encode("utf-8", "replace")
    truncated = len(raw) > MAX_PATCH_BYTES
    if truncated:
        raw = raw[:MAX_PATCH_BYTES]
        notes.append(f"the diff is longer than {MAX_PATCH_BYTES} bytes and was cut there")
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    patch_path.write_bytes(raw)
    return {
        "repo": prepared.repo,
        "start": prepared.start,
        "files_changed": len(changed),
        "files": changed[:200],
        "insertions": insertions,
        "deletions": deletions,
        "patch_sha256": sha256_hex(raw),
        "patch_bytes": len(raw),
        "patch_path": str(patch_path),
        "truncated": truncated,
        "notes": notes,
    }
