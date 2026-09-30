#!/usr/bin/env python3
"""Seen-it-fire verifier: prove every hard gate in evals/registry.yaml fires.

For EVERY `blocking: hard` registry row this asserts, via real promote.py
subprocess runs (exit codes read directly — never through a pipe):

  1. coverage: a fixture evals/fixtures/block_<metric>.json exists
     (and no stray block_*.json exists for a non-hard metric);
  2. block:    promote.py on that fixture exits 1 AND its decision table
     shows BLOCK on exactly that metric (every other metric PASS);
  3. healthy:  promote.py on evals/fixtures/healthy.json exits 0.

The block fixtures are NOT hand-typed numbers: each is the measured output
of `go run ./cmd/evalrun --sabotage <mode>` — a real run of the scorer with
one genuine failure mode injected (see cmd/evalrun/main.go). The CI job also
regenerates one live to prove the sabotage path itself still works.

Exit 0 = every hard gate proven to fire; exit 1 = proof failed.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
REGISTRY = REPO / "evals/registry.yaml"
FIXTURES = REPO / "evals/fixtures"
PROMOTE = REPO / "evals/tools/promote.py"


def run_promote(candidate: Path) -> tuple[int, str]:
    r = subprocess.run(
        [sys.executable, str(PROMOTE), "--candidate", str(candidate)],
        cwd=REPO, capture_output=True, text=True,
    )
    return r.returncode, r.stdout + r.stderr


def table_statuses(output: str) -> dict[str, str]:
    """Parse `metric ... status reason` rows from promote's decision table."""
    statuses: dict[str, str] = {}
    for line in output.splitlines():
        m = re.match(r"^(\w+)\s+(?:hard|soft|monitor_only)\s+.*\b(PASS|WARN|BLOCK)\b", line)
        if m:
            statuses[m.group(1)] = m.group(2)
    return statuses


def main() -> int:
    rows = yaml.safe_load(REGISTRY.read_text())
    hard = sorted(r["name"] for r in rows if r.get("blocking") == "hard")
    have = sorted(p.stem.removeprefix("block_") for p in FIXTURES.glob("block_*.json"))

    failures: list[str] = []

    if hard != have:
        failures.append(
            f"coverage mismatch: hard metrics {hard} vs block fixtures {have} — "
            f"a new hard row REQUIRES a new proven block fixture"
        )

    for metric in hard:
        fixture = FIXTURES / f"block_{metric}.json"
        if not fixture.exists():
            continue  # already reported by the coverage check
        code, out = run_promote(fixture)
        statuses = table_statuses(out)
        if code != 1:
            failures.append(f"{fixture.name}: promote exited {code}, want 1 (BLOCK)")
            continue
        if statuses.get(metric) != "BLOCK":
            failures.append(
                f"{fixture.name}: metric {metric} status {statuses.get(metric)!r}, want BLOCK"
            )
        others = {m: s for m, s in statuses.items() if m != metric and s == "BLOCK"}
        if others:
            failures.append(
                f"{fixture.name}: fixture must breach ONLY {metric}, but also blocks {sorted(others)}"
            )
        print(f"  PROVEN: {metric} gate fires (exit 1, BLOCK on exactly that metric)")

    healthy = FIXTURES / "healthy.json"
    code, _ = run_promote(healthy)
    if code != 0:
        failures.append(f"healthy.json: promote exited {code}, want 0 (PROMOTE)")
    else:
        print("  PROVEN: healthy candidate PROMOTEs (exit 0)")

    if failures:
        print("\nSEEN-IT-FIRE VERIFICATION FAILED:", file=sys.stderr)
        for f in failures:
            print("  -", f, file=sys.stderr)
        return 1
    print(f"\nAll {len(hard)} hard gates proven to fire; healthy run promotes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
