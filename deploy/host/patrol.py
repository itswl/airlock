#!/usr/bin/env python3
"""Patrol this host: collect a snapshot of facts and post it to airlock as one signed signal.

    python3 patrol.py --url http://127.0.0.1:8080/v1/intake/patrol --secret-file <file>

Standard library only, so it runs on the host as it is (cron-friendly). It
collects aggregates and nothing that names anything else running here: disk
and memory pressure, load, Docker's reclaimable space, containers by state,
pending package updates, whether a reboot is waiting. The snapshot goes to
the investigator as the signal's body; the investigator reads it and nothing
else of the host.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path


def sh(*argv: str) -> str:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def facts() -> dict:
    meminfo = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines() if ":" in line)
    kb = lambda key: int(meminfo.get(key, "0 kB").split()[0])  # noqa: E731
    disk = shutil.disk_usage("/")
    states: dict[str, int] = {}
    for state in sh("docker", "ps", "-a", "--format", "{{.State}}").split():
        states[state] = states.get(state, 0) + 1
    system_df = [
        json.loads(line) for line in sh("docker", "system", "df", "--format", "{{json .}}").splitlines() if line.strip()
    ]
    upgradable = [line for line in sh("apt", "list", "--upgradable").splitlines() if "upgradable" in line]
    return {
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "uptime_days": round(float(Path("/proc/uptime").read_text().split()[0]) / 86400, 1),
        "cpus": os.cpu_count(),
        "load_1_5_15": Path("/proc/loadavg").read_text().split()[:3],
        "memory": {"total_mb": kb("MemTotal") // 1024, "available_mb": kb("MemAvailable") // 1024},
        "root_disk": {"total_gb": round(disk.total / 1e9, 1), "used_percent": round(100 * disk.used / disk.total, 1)},
        "docker": {
            "containers_by_state": states,
            "unhealthy": len(sh("docker", "ps", "-q", "--filter", "health=unhealthy").split()),
            "dangling_images": len(sh("docker", "images", "-q", "-f", "dangling=true").split()),
            "space": [
                {k: row.get(k) for k in ("Type", "TotalCount", "Active", "Size", "Reclaimable")} for row in system_df
            ],
        },
        "packages": {
            "upgradable": len(upgradable),
            "security_upgradable": sum(1 for line in upgradable if "security" in line),
            "reboot_required": Path("/var/run/reboot-required").exists(),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", required=True)
    parser.add_argument("--secret-file", required=True)
    parser.add_argument("--print", action="store_true", help="print the snapshot instead of sending it")
    args = parser.parse_args()
    snapshot = facts()
    if args.print:
        print(json.dumps(snapshot, indent=2))
        return 0
    body = json.dumps({"patrol": snapshot, "collected_at": snapshot["collected_at"]}).encode()
    secret = Path(args.secret_file).read_text().strip()
    stamp = str(int(time.time()))
    signature = "sha256=" + hmac.new(secret.encode(), stamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    if not args.url.startswith(("http://", "https://")):
        raise SystemExit("--url must be http(s)")
    request = urllib.request.Request(  # noqa: S310 — checked just above
        args.url,
        data=body,
        headers={"Content-Type": "application/json", "X-Airlock-Timestamp": stamp, "X-Airlock-Signature": signature},
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 — the operator's own control plane
        print(response.status, response.read().decode()[:200])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
