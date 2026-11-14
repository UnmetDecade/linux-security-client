#!/usr/bin/env python3
"""Enforce per-file coverage floors in addition to the global threshold.

Coverage.py only supports a single global ``fail_under`` value. The modules
below sit on the critical path of the product (HTTP API, authentication, event
mapping, host checks, rule-pack verification, quarantine, Docker API client,
storage), so they get their own floors set slightly below the measured value.

Usage:
    python3 scripts/check-coverage.py [coverage.json]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

GLOBAL_MIN = 64.0

THRESHOLDS = {
    "src/lsec/api/server.py": 76.0,
    "src/lsec/api/auth.py": 63.0,
    "src/lsec/core/events.py": 88.0,
    "src/lsec/core/hostchecks.py": 75.0,
    "src/lsec/core/yara.py": 84.0,
    "src/lsec/core/quarantine.py": 78.0,
    "src/lsec/core/docker_api.py": 62.0,
    "src/lsec/storage/db.py": 71.0,
}


def normalise(name: str) -> str:
    return name.replace("\\", "/").lstrip("./")


def main() -> int:
    report_path = Path(sys.argv[1] if len(sys.argv) > 1 else "coverage.json")
    data = json.loads(report_path.read_text(encoding="utf-8"))
    files = {normalise(name): info for name, info in data["files"].items()}
    failures: list[str] = []

    total = float(data["totals"]["percent_covered"])
    status = "ok" if total >= GLOBAL_MIN else "FAIL"
    print(f"{status:4}  global coverage {total:.1f}% (minimum {GLOBAL_MIN:.0f}%)")
    if total < GLOBAL_MIN:
        failures.append(f"global coverage {total:.1f}% < {GLOBAL_MIN:.0f}%")

    for name, minimum in sorted(THRESHOLDS.items()):
        info = files.get(name)
        if info is None:
            print(f"FAIL  {name}: not present in the coverage report")
            failures.append(f"{name}: missing from coverage report")
            continue
        actual = float(info["summary"]["percent_covered"])
        status = "ok" if actual >= minimum else "FAIL"
        print(f"{status:4}  {name}: {actual:.1f}% (minimum {minimum:.0f}%)")
        if actual < minimum:
            failures.append(f"{name}: {actual:.1f}% < {minimum:.0f}%")

    if failures:
        print("\nCoverage requirements not met:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
