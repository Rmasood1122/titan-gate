"""WO-3.5b AT — titan-verify --chain on TRS-2 chains (profile dispatch
at the third-party verifier). Golden WO-2 TRS-1 behavior untouched —
pinned by the existing suite.

Pins:
  1. Pure TRS-2 chain (dir + jsonl) verifies with --pubkey only.
  2. Body tamper / prev tamper FAIL with position.
  3. Mid-chain profile flip -> ERR_CHAIN_PROFILE_MISMATCH with position.
  4. TRS-2 chain without --pubkey -> ERR_PUBKEY_REQUIRED (HMAC is
     meaningless for TRS-2; no key can make it verify).
  5. Unknown profile at genesis -> ERR_SCHEMA_VERSION at position 0.

Expected first run: RED (positives fail with ERR_SCHEMA_VERSION,
since _check_receipt_silent rejects non-receipt_v1).
"""
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from titan_gate.verify import _verify_chain
from titan_gate.trs2 import build_trs2_event
from titan_gate.trs2_writer import build_trs2_receipt

_PRIV = Ed25519PrivateKey.generate()
_PUB_HEX = _PRIV.public_key().public_bytes_raw().hex()

def sign_fn(d): return _PRIV.sign(d)

def _event(n):
    return build_trs2_event(
        source_id="src", source_event_id=f"e{n:04d}",
        event_time="2026-08-06T12:00:00Z", ingest_time="2026-08-06T12:00:41Z",
        agent_ref="agent-1", principal_ref="user:p",
        action=dict(category="data_access", operation="read",
                    target_hash="a"*64, attributes_hash="b"*64),
        outcome=dict(value="success"))

def _chain(n=3):
    prev, out = "GENESIS", []
    for i in range(n):
        r = build_trs2_receipt(event=_event(i), tenant_id="t", seq=i,
                               prev_receipt_hash=prev, sign_fn=sign_fn,
                               key_id="k1")
        out.append(r)
        prev = r["receipt_hash"]
    return out

def _write_dir(tmp_path, receipts):
    d = tmp_path / "chain"
    d.mkdir()
    for i, r in enumerate(receipts):
        (d / f"r_{i:04d}.json").write_text(json.dumps(r), encoding="utf-8")
    return str(d)

def _write_jsonl(tmp_path, receipts):
    p = tmp_path / "chain.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in receipts), encoding="utf-8")
    return str(p)

def _pubkey_file(tmp_path):
    p = tmp_path / "pub.hex"
    p.write_text(_PUB_HEX, encoding="utf-8")
    return str(p)

def _run(capsys, path, pubkey=None, key=None):
    rc = _verify_chain(path, key, pubkey, "json", False)
    out = json.loads(capsys.readouterr().out)
    return rc, out


def test_pure_trs2_dir_passes(tmp_path, capsys):
    rc, out = _run(capsys, _write_dir(tmp_path, _chain(3)),
                   pubkey=_pubkey_file(tmp_path))
    assert rc == 0 and out["ok"] is True and out["receipts_checked"] == 3

def test_pure_trs2_jsonl_passes(tmp_path, capsys):
    rc, out = _run(capsys, _write_jsonl(tmp_path, _chain(3)),
                   pubkey=_pubkey_file(tmp_path))
    assert rc == 0 and out["ok"] is True

def test_body_tamper_fails_with_position(tmp_path, capsys):
    rs = _chain(3)
    rs[1]["event"]["outcome"]["value"] = "denied"
    rc, out = _run(capsys, _write_dir(tmp_path, rs),
                   pubkey=_pubkey_file(tmp_path))
    assert rc == 1 and out["ok"] is False and out["break_position"] == 1

def test_deleted_receipt_fails_with_position(tmp_path, capsys):
    rs = _chain(3)
    del rs[1]  # r2.prev no longer matches r0.hash
    rc, out = _run(capsys, _write_dir(tmp_path, rs),
                   pubkey=_pubkey_file(tmp_path))
    assert rc == 1 and out["err_code"] == "ERR_CHAIN_BROKEN" \
        and out["break_position"] == 1

def test_profile_flip_midchain_fails_named(tmp_path, capsys):
    rs = _chain(3)
    rs[2]["schema_version"] = "receipt_v1"
    rc, out = _run(capsys, _write_dir(tmp_path, rs),
                   pubkey=_pubkey_file(tmp_path))
    assert rc == 1 and out["err_code"] == "ERR_CHAIN_PROFILE_MISMATCH" \
        and out["break_position"] == 2

def test_trs2_without_pubkey_requires_it(tmp_path, capsys):
    rc, out = _run(capsys, _write_dir(tmp_path, _chain(2)))
    assert rc != 0 and out["err_code"] == "ERR_PUBKEY_REQUIRED"

def test_unknown_profile_at_genesis_no_fallback(tmp_path, capsys):
    rs = _chain(1)
    rs[0]["schema_version"] = "receipt_trs9_v1"
    rc, out = _run(capsys, _write_dir(tmp_path, rs),
                   pubkey=_pubkey_file(tmp_path))
    assert rc == 1 and out["err_code"] == "ERR_SCHEMA_VERSION" \
        and out["break_position"] == 0
