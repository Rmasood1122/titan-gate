#!/usr/bin/env python3
"""titan-gate release-gate adapter (eval-conductor consumer).

Runs the 24-probe adversarial battery (probe_24.py — offline, seconds) and
turns its verdicts into a fail-closed release decision. probe_24 itself
always exits 0: before this gate, a FAIL verdict was a printed sentence
("claims-discipline incident") that CI ignored. Now it blocks the release.

Emits candidate/v2 for the vendored gate (evals/tools/promote.py):

  {"manifest": {"schema": "candidate/v2",
                "registry_hash": sha256(evals/registry.yaml),   # VERIFIED by the gate
                "dataset_hash":  sha256(sorted gated inputs)},  # attestation
   "scores": {...}}

Metrics (see evals/registry.yaml):
  probe_verdict_match_rate  P01..P23 verdicts EXACTLY equal the sealed
                            expectations (evals/probe_expectations.yaml).
                            A PROVEN capability regressing blocks; a
                            NOT-BUILT gap silently becoming built blocks
                            too — update the seal in the same reviewed
                            commit (absence is recorded, not implied).
  chain_2k_verify_s         measured seconds for the 2k-receipt full-verify
                            inside probe P24 (timing-dependent, so its
                            VERDICT is deliberately unsealed; its NUMBER is
                            the soft ops metric).

Honest run (CI):  python3 evals/run_evals.py
BLOCK fixture:    python3 evals/run_evals.py --sabotage expectations --out <path>

Sabotage mode exists ONLY to prove the gate fires (seen-it-fire doctrine):
  expectations  the match is recomputed against a seal with one verdict
                flipped — modelling a drifted or tampered expectations file
                (the seal is the anchor; corrupt the anchor, the gate blocks).

All subprocess exit codes are read directly — no gating signal crosses a pipe.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
PROBE = REPO / "probe_24.py"
EXPECTATIONS = REPO / "evals/probe_expectations.yaml"

GATED_INPUTS = [
    "probe_24.py",
    "evals/probe_expectations.yaml",
]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_probes() -> list[dict]:
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "probes.json"
        r = subprocess.run(
            [sys.executable, str(PROBE)],
            cwd=REPO, capture_output=True, text=True,
            env={**__import__("os").environ, "TITAN_PROBE_JSON": str(out)},
        )
        if r.returncode != 0:
            raise SystemExit(f"FAIL: probe_24.py exited {r.returncode}:\n{r.stdout}{r.stderr}")
        if not out.exists():
            raise SystemExit("FAIL: probe_24.py wrote no JSON — TITAN_PROBE_JSON emitter missing")
        probes = json.loads(out.read_text(encoding="utf-8"))
    if len(probes) != 24:
        raise SystemExit(f"FAIL: expected 24 probes, got {len(probes)}")
    return probes


def verdict_match_rate(probes: list[dict], expectations: dict[str, str]) -> tuple[float, list[str]]:
    sealed = {int(k[1:]): v for k, v in expectations.items()}
    if sorted(sealed) != list(range(1, 24)):
        raise SystemExit("FAIL: expectations must seal exactly P01..P23")
    mismatches: list[str] = []
    for p in probes:
        n = p["probe"]
        if n == 24:
            continue  # timing-dependent verdict — its number is gated, not its verdict
        if p["verdict"] != sealed[n]:
            mismatches.append(f"P{n:02d}: sealed {sealed[n]!r}, measured {p['verdict']!r} ({p['name']})")
    rate = (23 - len(mismatches)) / 23
    return rate, mismatches


def chain_seconds(probes: list[dict]) -> float:
    p24 = next(p for p in probes if p["probe"] == 24)
    m = re.search(r"2k full-verify ([0-9.]+)s", p24["note"] or "")
    if not m:
        raise SystemExit(f"FAIL: cannot read 2k-verify seconds from P24 note: {p24['note']!r}")
    return float(m.group(1))


def dataset_hash() -> str:
    h = hashlib.sha256()
    for rel in sorted(GATED_INPUTS):
        p = REPO / rel
        h.update(rel.encode()); h.update(b"\0")
        h.update(p.read_bytes()); h.update(b"\0")
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(REPO / "evals/candidate.json"))
    ap.add_argument("--registry", default=str(REPO / "evals/registry.yaml"))
    ap.add_argument("--sabotage", default="", choices=["", "expectations"])
    a = ap.parse_args()

    expectations = yaml.safe_load(EXPECTATIONS.read_text())["expectations"]
    probes = run_probes()

    rate, mismatches = verdict_match_rate(probes, expectations)
    scores = {
        "probe_verdict_match_rate": rate,
        "chain_2k_verify_s": chain_seconds(probes),
    }

    if a.sabotage == "expectations":
        corrupted = dict(expectations)
        corrupted["P02"] = "NOT-BUILT"  # flip one sealed capability verdict
        rate2, mismatches = verdict_match_rate(probes, corrupted)
        scores["probe_verdict_match_rate"] = rate2

    cand = {
        "manifest": {
            "schema": "candidate/v2",
            "registry_hash": sha256_file(Path(a.registry)),
            "dataset_hash": dataset_hash(),
        },
        "scores": scores,
    }
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cand, indent=2) + "\n", encoding="utf-8")

    mode = "honest" if not a.sabotage else f"SABOTAGE:{a.sabotage}"
    print(f"run_evals ({mode}): wrote {out}")
    for k in sorted(scores):
        print(f"  {k:26s} {scores[k]:.6f}")
    for msg in mismatches:
        print(f"  MISMATCH {msg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
