"""WO-6 AT: chain walk for receipt_trs2_v2 chains, via public dispatch.

Spec (SPEC-2 amendment, companion to test_wo6_receipt_type.py):
  - Genesis schema_version receipt_trs2_v2 dispatches a v2 chain walk.
  - Gap and marker receipts are ORDINARY LINKS: an intact chain of
    action -> gap -> marker -> action PASSes. Disclosure of gaps is a
    report concern, never a chain-validity concern (FR-ING-6: signed
    gap receipts flow through the chain like everything else).
  - Deletion and reordering FAIL with position (ERR_CHAIN_BROKEN).
  - One profile per chain: a v1 receipt inside a v2 chain (or v2 in
    v1) FAILs ERR_CHAIN_PROFILE_MISMATCH at its position.
  - v2 chains require --pubkey (no HMAC mode; exit 2, same as v1).
  - v1 chain walking is golden: byte-behavior unchanged.

Tested through _verify_chain (path in, exit code out, JSON report on
stdout) so the walk's internal shape — parameterized vs separate —
is not pinned by this AT.
"""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from titan_gate.trs2 import build_trs2_event
from titan_gate.trs2_writer import (
    build_trs2_receipt,      # v1 (golden)
    build_trs2_receipt_v2,   # v2 (2dc6bee)
)
from titan_gate.verify import _verify_chain

H_TARGET = "b" * 64


@pytest.fixture()
def keys():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


@pytest.fixture()
def sign_fn(keys):
    priv, _ = keys
    return lambda digest: priv.sign(digest)


@pytest.fixture()
def pub_path(tmp_path, keys):
    priv, _ = keys
    raw = priv.public_key().public_bytes_raw()
    p = tmp_path / "tenant.pub"
    p.write_text(raw.hex(), encoding="utf-8")
    return str(p)


def _event(n: int) -> dict:
    return build_trs2_event(
        source_id="m365-audit",
        source_event_id=f"evt-{n:04d}",
        event_time=f"2026-08-06T10:{n:02d}:00Z",
        ingest_time=f"2026-08-06T10:{n:02d}:30Z",
        agent_ref="agent://copilot/finance-bot",
        principal_ref="user://alice@example.com",
        action={"category": "data_access", "operation": "read",
                "target_hash": H_TARGET, "attributes_hash": H_TARGET},
        outcome={"value": "success"},
    )


def _build_v2_chain(sign_fn):
    """action -> gap(open) -> marker(close) -> action. Returns receipts."""
    receipts = []
    prev = "GENESIS"
    specs = [
        ("action", {"event": _event(0)}),
        ("gap", {"gap": {"source_id": "m365-audit",
                         "interval_start": "2026-08-06T10:05:00Z"}}),
        ("marker", {"gap": {"source_id": "m365-audit",
                            "interval_start": "2026-08-06T10:05:00Z",
                            "interval_end": "2026-08-06T10:15:00Z"}}),
        ("action", {"event": _event(3)}),
    ]
    for seq, (rtype, content) in enumerate(specs):
        r = build_trs2_receipt_v2(receipt_type=rtype, tenant_id="tenant-1",
                                  seq=seq, prev_receipt_hash=prev,
                                  sign_fn=sign_fn, key_id="k1", **content)
        receipts.append(r)
        prev = r["receipt_hash"]
    return receipts


def _write_chain(tmp_path, receipts, name="chain"):
    d = tmp_path / name
    d.mkdir()
    for i, r in enumerate(receipts):
        (d / f"{i:03d}.json").write_text(
            json.dumps(r), encoding="utf-8")
    return d


def _run(chain_dir, pub_path, capsys):
    code = _verify_chain(str(chain_dir), None, pub_path, "json", False)
    out = capsys.readouterr().out.strip()
    # _chain_output emits ONE json.dumps(..., indent=2) object per run:
    # parse the whole capture, never a single line.
    report = json.loads(out) if out else {}
    return code, report


# ------------------------------------------------------------------ dispatch

def test_v2_intact_chain_with_gap_and_marker_passes(
        tmp_path, sign_fn, pub_path, capsys):
    receipts = _build_v2_chain(sign_fn)
    d = _write_chain(tmp_path, receipts)
    code, report = _run(d, pub_path, capsys)
    assert code == 0
    assert report["ok"] is True
    assert report["receipts_checked"] == 4


def test_v2_requires_pubkey(tmp_path, sign_fn, capsys):
    receipts = _build_v2_chain(sign_fn)
    d = _write_chain(tmp_path, receipts)
    code = _verify_chain(str(d), None, None, "json", False)
    out = capsys.readouterr().out.strip()
    report = json.loads(out)
    assert code == 2
    assert report["err_code"] == "ERR_PUBKEY_REQUIRED"


# ----------------------------------------------------------- tamper classes

def test_v2_deletion_fails_with_position(tmp_path, sign_fn, pub_path, capsys):
    receipts = _build_v2_chain(sign_fn)
    d = _write_chain(tmp_path, receipts)
    (d / "001.json").unlink()  # delete the gap receipt itself
    code, report = _run(d, pub_path, capsys)
    assert code == 1
    assert report["err_code"] == "ERR_CHAIN_BROKEN"
    # After deleting file 001, the old position-2 receipt sits at
    # walk position 1 and its prev no longer matches position 0.
    assert report["break_position"] == 1


def test_v2_reorder_fails_with_position(tmp_path, sign_fn, pub_path, capsys):
    receipts = _build_v2_chain(sign_fn)
    d = _write_chain(tmp_path, receipts)
    a = (d / "001.json").read_text(encoding="utf-8")
    b = (d / "002.json").read_text(encoding="utf-8")
    (d / "001.json").write_text(b, encoding="utf-8")
    (d / "002.json").write_text(a, encoding="utf-8")
    code, report = _run(d, pub_path, capsys)
    assert code == 1
    assert report["err_code"] == "ERR_CHAIN_BROKEN"
    assert report["break_position"] == 1


def test_v2_mixed_version_fails_profile_mismatch(
        tmp_path, sign_fn, pub_path, capsys):
    receipts = _build_v2_chain(sign_fn)
    # Replace position 3 with a v1 receipt correctly LINKED to position
    # 2 — so only the profile check can catch it, not the linkage check.
    v1 = build_trs2_receipt(event=_event(3), tenant_id="tenant-1", seq=3,
                            prev_receipt_hash=receipts[2]["receipt_hash"],
                            sign_fn=sign_fn, key_id="k1")
    receipts[3] = v1
    d = _write_chain(tmp_path, receipts)
    code, report = _run(d, pub_path, capsys)
    assert code == 1
    assert report["err_code"] == "ERR_CHAIN_PROFILE_MISMATCH"
    assert report["break_position"] == 3


def test_v1_receipt_at_genesis_of_v2_files_dispatches_v1_walk(
        tmp_path, sign_fn, pub_path, capsys):
    """Genesis declares the profile. A v1 receipt at position 0 followed
    by v2 receipts dispatches the v1 walk, which must then refuse the
    v2 receipts (profile mismatch) — never half-verify them."""
    receipts = _build_v2_chain(sign_fn)
    v1_genesis = build_trs2_receipt(event=_event(0), tenant_id="tenant-1",
                                    seq=0, prev_receipt_hash="GENESIS",
                                    sign_fn=sign_fn, key_id="k1")
    receipts[0] = v1_genesis
    d = _write_chain(tmp_path, receipts)
    code, report = _run(d, pub_path, capsys)
    assert code == 1
    assert report["err_code"] in ("ERR_CHAIN_PROFILE_MISMATCH",
                                  "ERR_CHAIN_BROKEN")


# ------------------------------------------------------------- v1 golden pin

def test_v1_chain_still_walks_green(tmp_path, sign_fn, pub_path, capsys):
    receipts, prev = [], "GENESIS"
    for seq in range(3):
        r = build_trs2_receipt(event=_event(seq), tenant_id="tenant-1",
                               seq=seq, prev_receipt_hash=prev,
                               sign_fn=sign_fn, key_id="k1")
        receipts.append(r)
        prev = r["receipt_hash"]
    d = _write_chain(tmp_path, receipts)
    code, report = _run(d, pub_path, capsys)
    assert code == 0
    assert report["ok"] is True
    assert report["receipts_checked"] == 3
