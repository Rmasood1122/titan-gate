"""Guard: the ONLY permitted collection error is a known TDD-red module.

Without this, an accidental broken import (typo, bad refactor) hides
inside pytest's "1 error" line while the green count still looks fine.
This makes an UNEXPECTED collection error a hard failure, and forces
KNOWN_RED to shrink as work lands (a fixed module still listed is stale
weight — PROCESS.md S6). Uses --continue-on-collection-errors so the
guard itself never self-aborts on the known red."""
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Modules intentionally RED (test written before implementation, TDD D1).
KNOWN_RED = set()  # empty: WO-8-core bundle_v2 landed green


def _collection_errors() -> set:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "--continue-on-collection-errors", "-p", "no:cacheprovider"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    errors = set()
    for line in proc.stdout.splitlines():
        m = re.match(r"^ERROR\s+(\S+)", line.strip())
        if m:
            errors.add(m.group(1).replace("\\", "/"))
    return errors


def test_no_unexpected_collection_errors():
    unexpected = _collection_errors() - KNOWN_RED
    assert not unexpected, f"New collection errors: {sorted(unexpected)}"


def test_known_red_modules_are_still_red():
    # If a KNOWN_RED module now collects, the impl landed — prune the list.
    fixed = KNOWN_RED - _collection_errors()
    assert not fixed, f"Now collecting; remove from KNOWN_RED: {sorted(fixed)}"
