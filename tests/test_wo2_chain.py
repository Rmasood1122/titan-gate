"""WO-2 acceptance tests: titan-verify --chain (chain-walk verification, kills G2).

Contract being tested (implementation follows AFTER this is red):
  titan-verify --chain <dir|file.jsonl> [--key HEX] [--pubkey FILE] [--format json]

  - A directory: receipts are *.json files; claimed order = lexicographic filename order.
  - A .jsonl file: one receipt per line; claimed order = line order.
  - Receipt 0 MUST have prev_receipt_hash == "GENESIS".
  - For every n >= 1: receipt[n].prev_receipt_hash must equal receipt[n-1].receipt_hash.
  - Every receipt is also individually verified (hash + signature) via the existing
    per-receipt dispatch on signing_version (--key for hmac-sha256-v1, --pubkey for
    ed25519-v1; both may be supplied; mixed chains are legal).
  - JSON output contract (chain mode):
      ok: bool, result: "VALID"|"INVALID", receipts_checked: int,
      err_code: None | "ERR_CHAIN_BROKEN" | "ERR_CHAIN_GENESIS" | per-receipt codes,
      break_position: None | int  (0-based index in claimed order where the walk failed),
      message: str | None
  - Exit codes: 0 chain valid, 1 chain/receipt invalid, 2 usage/environment error.

RUN ORDER:
  1. Run now against current verify.py -> BOTH tests FAIL (red): --chain doesn't exist.
  2. Implementation lands, re-run -> green, then full-suite regression, then commit.
"""
import json
import os
import subprocess
import sys
import time

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERIFY_PY = os.path.join(REPO_ROOT, "titan_gate", "verify.py")

sys.path.insert(0, REPO_ROOT)

from api.receipt_signing import compute_receipt_hash, compute_signature  # noqa: E402

HMAC_KEY = "cd" * 32


def _receipt_n(n, prev_hash):
    """Fully valid TRS-1/HMAC receipt, linked to prev_hash."""
    r = {
        "schema_version": "receipt_v1",
        "receipt_id": f"r-chain-{n:06d}",
        "tenant_id": "t-test",
        "repo": "titan-gate",
        "repo_full_name": "example/titan-gate",
        "pr_number": n,
        "evaluated_at": f"2026-08-05T00:00:00Z",
        "root_date": "2026-08-05",
        "engine_version": "test",
        "contract_version": "test",
        "scoring_formula_version": "test",
        "policy_version": "test",
        "merkle_algorithm": "merkle_v1",
        "signing_version": "hmac-sha256-v1",
        "structural_score": 1,
        "semantic_score": 1,
        "composite_score": 1,
        "verdict": "PASS",
        "hard_violations": [],
        "process_violations": [],
        "artifact_hash": "a" * 64,
        "scope_hash": "b" * 64,
        "provenance_hash": "c" * 64,
        "prev_receipt_hash": prev_hash,
        "receipt_hash": "",
        "signature": "",
        "ai_attributed": True,
    }
    r["receipt_hash"] = compute_receipt_hash(r)
    r["signature"] = compute_signature(r, HMAC_KEY)
    return r


def _build_chain(length):
    receipts = []
    prev = "GENESIS"
    for n in range(length):
        r = _receipt_n(n, prev)
        receipts.append(r)
        prev = r["receipt_hash"]
    return receipts


def _write_chain_dir(tmp_path, receipts, name="chain"):
    d = tmp_path / name
    d.mkdir()
    for i, r in enumerate(receipts):
        (d / f"{i:06d}.json").write_text(json.dumps(r), encoding="utf-8")
    return d


def _run(args):
    cmd = [sys.executable, VERIFY_PY, *args]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)


# ---------------------------------------------------------------------------
# AT-A — tamper detection with position
# ---------------------------------------------------------------------------

def test_chain_tamper_detection(tmp_path):
    receipts = _build_chain(100)

    # 1. Intact chain of 100 -> PASS.
    d = _write_chain_dir(tmp_path, receipts, "intact")
    proc = _run(["--chain", str(d), "--key", HMAC_KEY, "--format", "json"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = json.loads(proc.stdout)
    assert out["ok"] is True
    assert out["result"] == "VALID"
    assert out["receipts_checked"] == 100
    assert out["err_code"] is None
    assert out["break_position"] is None

    # 2. Delete the middle receipt (index 50) -> FAIL naming the position.
    d = _write_chain_dir(tmp_path, receipts, "hole")
    os.remove(d / "000050.json")
    proc = _run(["--chain", str(d), "--key", HMAC_KEY, "--format", "json"])
    assert proc.returncode == 1
    out = json.loads(proc.stdout)
    assert out["ok"] is False
    assert out["err_code"] == "ERR_CHAIN_BROKEN"
    # After removing index 50, the break is detected at claimed position 50
    # (the old index-51 receipt, whose prev no longer matches).
    assert out["break_position"] == 50
    assert "50" in (out["message"] or "")

    # 3. Swap two adjacent receipts (30 <-> 31) -> FAIL at the first bad link.
    d = _write_chain_dir(tmp_path, receipts, "swap")
    a = (d / "000030.json").read_text(encoding="utf-8")
    b = (d / "000031.json").read_text(encoding="utf-8")
    (d / "000030.json").write_text(b, encoding="utf-8")
    (d / "000031.json").write_text(a, encoding="utf-8")
    proc = _run(["--chain", str(d), "--key", HMAC_KEY, "--format", "json"])
    assert proc.returncode == 1
    out = json.loads(proc.stdout)
    assert out["err_code"] == "ERR_CHAIN_BROKEN"
    assert out["break_position"] == 30

    # 4. Non-genesis start: drop receipt 0 -> distinct genesis error at position 0.
    d = _write_chain_dir(tmp_path, receipts, "nogen")
    os.remove(d / "000000.json")
    proc = _run(["--chain", str(d), "--key", HMAC_KEY, "--format", "json"])
    assert proc.returncode == 1
    out = json.loads(proc.stdout)
    assert out["err_code"] == "ERR_CHAIN_GENESIS"
    assert out["break_position"] == 0

    # 5. A tampered BODY mid-chain fails per-receipt verification, not just
    #    linkage: mutate a signed field in receipt 70 without touching hashes.
    d = _write_chain_dir(tmp_path, receipts, "bodytamper")
    r70 = json.loads((d / "000070.json").read_text(encoding="utf-8"))
    r70["verdict"] = "FAIL"
    (d / "000070.json").write_text(json.dumps(r70), encoding="utf-8")
    proc = _run(["--chain", str(d), "--key", HMAC_KEY, "--format", "json"])
    assert proc.returncode == 1
    out = json.loads(proc.stdout)
    assert out["break_position"] == 70


# ---------------------------------------------------------------------------
# AT-B — intact 10k chain verifies, under 5 seconds
# ---------------------------------------------------------------------------

def test_chain_10k_performance(tmp_path):
    receipts = _build_chain(10_000)
    d = _write_chain_dir(tmp_path, receipts, "big")

    start = time.monotonic()
    proc = _run(["--chain", str(d), "--key", HMAC_KEY, "--format", "json"])
    elapsed = time.monotonic() - start

    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = json.loads(proc.stdout)
    assert out["ok"] is True
    assert out["receipts_checked"] == 10_000
    assert elapsed < 5.0, f"chain verification took {elapsed:.2f}s (budget 5s)"
