"""WO-3.5a AT — chain_state profile dispatch (SPEC-2 §1.3: one profile
per chain, selected at genesis, canonicalizations non-interchangeable).

Pins:
  1. A pure TRS-2 chain on disk validates; latest_receipt_hash returns
     the true head (recomputed under JCS body-digest rules, NOT TRS-1
     sorted-keys — the digests differ, so a walker using the wrong
     recompute cannot pass these tests by accident).
  2. Tampering a TRS-2 receipt body on disk is detected.
  3. A mixed-profile tree hard-errors — mid-chain schema_version flip
     is the adversarial case (flipping the version changes which
     recompute runs; must FAIL, never tolerate).
  4. Unknown schema_version at genesis hard-errors; no silent TRS-1
     fallback (a walker that defaults its canonicalization can be steered).
  5. Existing TRS-1 trees still validate byte-identically (golden
     behavior — exercised by the untouched WO-3 tests, re-asserted here
     via one smoke case if a TRS-1 fixture helper exists; otherwise the
     existing suite is the pin).

Expected first run: RED.
"""
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from titan_gate.chain_state import latest_receipt_hash, ChainStateError
from titan_gate.trs2 import build_trs2_event
from titan_gate.trs2_writer import build_trs2_receipt

_PRIV = Ed25519PrivateKey.generate()

def sign_fn(d): return _PRIV.sign(d)

def _event(n):
    return build_trs2_event(
        source_id="src", source_event_id=f"e{n:04d}",
        event_time="2026-08-06T12:00:00Z", ingest_time="2026-08-06T12:00:41Z",
        agent_ref="agent-1", principal_ref="user:p",
        action=dict(category="data_access", operation="read",
                    target_hash="a"*64, attributes_hash="b"*64),
        outcome=dict(value="success"))

def _write_trs2_chain(root, length=3):
    root.mkdir(parents=True, exist_ok=True)
    prev, receipts = "GENESIS", []
    for i in range(length):
        r = build_trs2_receipt(event=_event(i), tenant_id="t",
                               seq=i, prev_receipt_hash=prev,
                               sign_fn=sign_fn, key_id="k1")
        (root / f"receipt_{i:04d}.json").write_text(
            json.dumps(r), encoding="utf-8")
        receipts.append(r)
        prev = r["receipt_hash"]
    return receipts


def test_pure_trs2_chain_validates_and_returns_head(tmp_path):
    rs = _write_trs2_chain(tmp_path / "rcpts", 3)
    assert latest_receipt_hash(tmp_path / "rcpts") == rs[-1]["receipt_hash"]


def test_trs2_single_receipt_chain(tmp_path):
    rs = _write_trs2_chain(tmp_path / "rcpts", 1)
    assert latest_receipt_hash(tmp_path / "rcpts") == rs[0]["receipt_hash"]


def test_trs2_body_tamper_detected(tmp_path):
    _write_trs2_chain(tmp_path / "rcpts", 3)
    p = tmp_path / "rcpts" / "receipt_0001.json"
    r = json.loads(p.read_text(encoding="utf-8"))
    r["event"]["outcome"]["value"] = "denied"
    p.write_text(json.dumps(r), encoding="utf-8")
    with pytest.raises(ChainStateError):
        latest_receipt_hash(tmp_path / "rcpts")


def test_trs2_stored_hash_tamper_detected(tmp_path):
    _write_trs2_chain(tmp_path / "rcpts", 2)
    p = tmp_path / "rcpts" / "receipt_0001.json"
    r = json.loads(p.read_text(encoding="utf-8"))
    r["receipt_hash"] = "c" * 64
    p.write_text(json.dumps(r), encoding="utf-8")
    with pytest.raises(ChainStateError):
        latest_receipt_hash(tmp_path / "rcpts")


def test_mixed_profile_tree_hard_errors(tmp_path):
    rs = _write_trs2_chain(tmp_path / "rcpts", 3)
    p = tmp_path / "rcpts" / "receipt_0002.json"
    r = json.loads(p.read_text(encoding="utf-8"))
    r["schema_version"] = "receipt_v1"  # adversarial mid-chain flip
    p.write_text(json.dumps(r), encoding="utf-8")
    with pytest.raises(ChainStateError):
        latest_receipt_hash(tmp_path / "rcpts")
    del rs


def test_unknown_schema_version_hard_errors_no_fallback(tmp_path):
    _write_trs2_chain(tmp_path / "rcpts", 1)
    p = tmp_path / "rcpts" / "receipt_0000.json"
    r = json.loads(p.read_text(encoding="utf-8"))
    r["schema_version"] = "receipt_trs9_v1"
    p.write_text(json.dumps(r), encoding="utf-8")
    with pytest.raises(ChainStateError):
        latest_receipt_hash(tmp_path / "rcpts")
