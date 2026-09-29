"""WO-1 CLI acceptance tests for titan-verify.

AT-A  test_cli_pubkey_verify          — ed25519-v1 receipt verifies with the
                                        PUBLIC key file only; no secret appears
                                        anywhere in the invocation; tampering
                                        and wrong-key both FAIL.
AT-B  test_cli_legacy_hmac_unchanged  — legacy TRS-1/HMAC invocation produces
                                        byte-identical output (golden JSON dict
                                        equality + golden text block), and
                                        legacy error precedence is preserved.

RUN ORDER (this is the byte-identical proof, not just a regression):
  1. BEFORE applying the verify.py patch: run this file.
     -> AT-B must PASS against the CURRENT verify.py (it pins today's bytes).
     -> AT-A must FAIL (red) — --pubkey does not exist yet.
  2. Apply the patched verify.py.
  3. Re-run: both PASS. AT-B passing unchanged across the patch IS the
     byte-identical evidence for the legacy path.
  4. Full suite regression, then commit.
"""
import hashlib
import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
VERIFY_PY = os.path.join(REPO_ROOT, "titan_gate", "verify.py")

sys.path.insert(0, REPO_ROOT)

from api.receipt_signing import (  # noqa: E402
    canonical_bytes,
    compute_receipt_hash,
    compute_signature,
)
from api.signers import Ed25519Signer, generate_keypair  # noqa: E402

HMAC_KEY = "ab" * 32  # lowercase hex, as TRS-1 requires


def _base_receipt():
    """Minimal receipt satisfying every REQUIRED_FIELDS entry in verify.py."""
    return {
        "schema_version": "receipt_v1",
        "receipt_id": "r-cli-0001",
        "tenant_id": "t-test",
        "repo": "titan-gate",
        "repo_full_name": "example/titan-gate",
        "pr_number": 1,
        "evaluated_at": "2026-08-05T00:00:00Z",
        "root_date": "2026-08-05",
        "engine_version": "test",
        "contract_version": "test",
        "scoring_formula_version": "test",
        "policy_version": "test",
        "merkle_algorithm": "merkle_v1",
        "signing_version": "PLACEHOLDER",
        "structural_score": 1,
        "semantic_score": 1,
        "composite_score": 1,
        "verdict": "PASS",
        "hard_violations": [],
        "process_violations": [],
        "artifact_hash": "a" * 64,
        "scope_hash": "b" * 64,
        "provenance_hash": "c" * 64,
        "prev_receipt_hash": "GENESIS",
        "receipt_hash": "",
        "signature": "",
        "ai_attributed": True,
    }


def _write(tmp_path, name, obj_or_text):
    p = tmp_path / name
    if isinstance(obj_or_text, str):
        p.write_text(obj_or_text, encoding="utf-8")
    else:
        p.write_text(json.dumps(obj_or_text), encoding="utf-8")
    return str(p)


def _run(args):
    """Invoke the CLI exactly as an auditor would (fresh process, file path)."""
    cmd = [sys.executable, VERIFY_PY, *args]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    return proc, cmd


# ---------------------------------------------------------------------------
# AT-A — pubkey-only verification (kills G1 at the CLI edge)
# ---------------------------------------------------------------------------

def test_cli_pubkey_verify(tmp_path):
    priv_hex, pub_hex = generate_keypair()
    signer = Ed25519Signer(priv_hex)

    signed = signer.sign(_base_receipt())
    signed["receipt_hash"] = compute_receipt_hash(signed)

    receipt_path = _write(tmp_path, "receipt_ed.json", signed)
    pub_path = _write(tmp_path, "titan.pub", pub_hex + "\n")

    # 1. Verifies with the PUBLIC key file only.
    proc, cmd = _run([receipt_path, "--pubkey", pub_path, "--format", "json"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = json.loads(proc.stdout)
    assert out["ok"] is True
    assert out["result"] == "VALID"
    assert out["signature_valid"] is True
    assert out["receipt_hash_valid"] is True
    assert out["signing_version"] == "ed25519-v1"
    assert out["chain_status"] == "GENESIS"

    # 2. Standing rule §5.1: no secret anywhere in the auditor's invocation.
    invocation = " ".join(cmd)
    assert priv_hex not in invocation
    assert HMAC_KEY not in invocation
    pub_file_contents = open(pub_path, encoding="utf-8").read()
    assert priv_hex not in pub_file_contents

    # 3. Tamper: mutate a signed field -> FAIL (signature mismatch).
    tampered = dict(signed)
    tampered["verdict"] = "FAIL"
    t_path = _write(tmp_path, "receipt_tampered.json", tampered)
    proc, _ = _run([t_path, "--pubkey", pub_path, "--format", "json"])
    assert proc.returncode == 1
    out = json.loads(proc.stdout)
    assert out["ok"] is False
    assert out["err_code"] == "ERR_SIG"

    # 4. Downgrade attempt: rewrite signing_version -> signature breaks
    #    (signing_version is inside the signed body).
    downgraded = dict(signed)
    downgraded["signing_version"] = "hmac-sha256-v1"
    d_path = _write(tmp_path, "receipt_downgraded.json", downgraded)
    proc, _ = _run([d_path, "--key", HMAC_KEY, "--format", "json"])
    assert proc.returncode == 1  # routed to HMAC branch; sig can't validate

    # 5. Wrong public key -> FAIL.
    _, other_pub = generate_keypair()
    wrong_path = _write(tmp_path, "wrong.pub", other_pub + "\n")
    proc, _ = _run([receipt_path, "--pubkey", wrong_path, "--format", "json"])
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["err_code"] == "ERR_SIG"


# ---------------------------------------------------------------------------
# AT-B — legacy HMAC path byte-identical (golden outputs)
# ---------------------------------------------------------------------------

def _hmac_receipt():
    receipt = _base_receipt()
    receipt["signing_version"] = "hmac-sha256-v1"
    receipt["receipt_hash"] = compute_receipt_hash(receipt)
    receipt["signature"] = compute_signature(receipt, HMAC_KEY)
    return receipt


def test_cli_legacy_hmac_unchanged(tmp_path):
    receipt = _hmac_receipt()
    receipt_path = _write(tmp_path, "receipt_hmac.json", receipt)

    # Golden 1: full JSON dict equality — any added/removed/reordered key fails.
    proc, _ = _run([receipt_path, "--key", HMAC_KEY, "--format", "json"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    expected = {
        "ok": True,
        "result": "VALID",
        "err_code": None,
        "message": None,
        "receipt_id": "r-cli-0001",
        "receipt_hash": receipt["receipt_hash"],
        "signature_valid": True,
        "receipt_hash_valid": True,
        "chain_status": "GENESIS",
        "signing_version": "hmac-sha256-v1",
        "merkle_algorithm": "merkle_v1",
        "verdict": "PASS",
    }
    assert json.loads(proc.stdout) == expected

    # Golden 2: exact text-mode block, byte for byte.
    proc, _ = _run([receipt_path, "--key", HMAC_KEY])
    assert proc.returncode == 0
    expected_text = (
        "=" * 60 + "\n"
        "TITAN GATE RECEIPT VERIFICATION\n"
        + "=" * 60 + "\n"
        "Receipt ID   : r-cli-0001\n"
        "Tenant       : t-test\n"
        "Repo         : example/titan-gate\n"
        "Verdict      : PASS\n"
        "Score        : 1\n"
        "Evaluated At : 2026-08-05T00:00:00Z\n"
        + "-" * 60 + "\n"
        "VERIFICATION  : PASS\n"
        "Signature     : VALID\n"
        "Hash          : VALID\n"
        "Chain         : GENESIS\n"
        + "=" * 60 + "\n"
    )
    assert proc.stdout == expected_text

    # Golden 3: tamper -> exact legacy failure semantics.
    tampered = dict(receipt)
    sig = tampered["signature"]
    tampered["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    t_path = _write(tmp_path, "receipt_hmac_tampered.json", tampered)
    proc, _ = _run([t_path, "--key", HMAC_KEY, "--format", "json"])
    assert proc.returncode == 1
    out = json.loads(proc.stdout)
    assert out["err_code"] == "ERR_SIG"
    assert out["message"] == "ANOMALY: SIGNATURE_MISMATCH"

    # Golden 4: legacy error precedence preserved — uppercase key still
    # rejected with the same code and exit status, before field validation.
    proc, _ = _run([receipt_path, "--key", HMAC_KEY.upper(), "--format", "json"])
    assert proc.returncode == 2
    assert json.loads(proc.stdout)["err_code"] == "ERR_HEX_CASE_INVALID"
