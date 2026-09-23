"""Measure what a node's credentials can actually do, before it does anything.

"This investigator is read-only" is a declaration. The credentials mounted into
it decide, and nothing reads them but the far side. So each profile declares a
few checks — a command and what its answer must look like — and they run at
start (investigators) or before the first step (workers). A node whose checks do
not all pass refuses work: a boundary that exists only in a config file is not
one, and a node that starts anyway would spend its first run proving it.

    - name: cannot delete pods
      argv: [kubectl, auth, can-i, delete, pods, -A]
      expect: "^no"
    - name: is the dedicated worker identity
      argv: [aws, sts, get-caller-identity, --query, Arn, --output, text]
      expect: "user/airlock-worker-db$"

``expect`` is a regular expression searched in stdout and stderr together;
``exit`` optionally pins the exit code. A missing binary or a timeout fails.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping, Sequence
from typing import Any

TIMEOUT_SECONDS = 25.0


async def run_check(check: Mapping[str, Any], *, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    argv = [str(a) for a in check.get("argv") or []]
    name = str(check.get("name") or " ".join(argv[:4]))
    if not argv:
        return {"name": name, "ok": False, "detail": "no argv"}
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=dict(env) if env is not None else None,
        )
        try:
            out, err = await asyncio.wait_for(
                process.communicate(), timeout=float(check.get("timeout") or TIMEOUT_SECONDS)
            )
        except TimeoutError:
            process.kill()
            return {"name": name, "ok": False, "detail": "timed out"}
    except FileNotFoundError:
        return {"name": name, "ok": False, "detail": f"{argv[0]}: not found"}
    except OSError as exc:
        return {"name": name, "ok": False, "detail": str(exc)[:200]}
    text = (out.decode("utf-8", "replace") + "\n" + err.decode("utf-8", "replace")).strip()
    code = process.returncode
    ok = re.search(str(check.get("expect") or ""), text, re.MULTILINE) is not None
    if "exit" in check and code != int(check["exit"]):
        ok = False
    detail = text[-300:] if ok else f"exit {code}; got: {text[-300:]}"
    return {"name": name, "ok": ok, "detail": detail}


async def run_checks(
    checks: Sequence[Mapping[str, Any]], *, env: Mapping[str, str] | None = None
) -> list[dict[str, Any]]:
    return [await run_check(check, env=env) for check in checks]


def passed(results: Sequence[Mapping[str, Any]]) -> bool:
    return all(r.get("ok") for r in results)
