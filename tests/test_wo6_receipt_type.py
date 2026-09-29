"""WO-6 AT: TRS-2 v2 receipt_type spec extension (writer level).

Spec (SPEC-2 amendment, lands with this AT):
  - receipt_trs2_v2 adds REQUIRED receipt_type in {action, gap, marker}.
  - receipt_type lives INSIDE the signed body: relabeling a receipt's
    type after signing must fail verification.
  - action  -> carries `event` (titan_gate.trs2 profile), no `gap`.
  - gap     -> open declaration: gap {source_id, interval_start}, no event.
    Gaps are OUR statement about source silence, never a source
    statement — a gap carrying an outcome would forge recorded_by_source.
  - marker  -> close on recovery: gap {source_id, interval_start,
    interval_end}, no event.
  - gap/marker blocks are CLOSED sets with rebuild-equality (P11
    pattern) — no smuggling channel reopens under a new block name.
  - v1 (receipt_trs2_v1) is golden-pinned: still builds, still
    verifies, byte-behavior unchanged. Chains are version-homogeneous
    (chain-walk enforcement is the NEXT AT, after verify.py recon).

Every test here names symbols that do not exist yet. This file is the
failing AT for the WO-6 spec extension. Rule 2: nothing claimed until
this is green.
"""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from titan_gate.trs2 import build_trs2_event
from titan_gate.trs2_writer import (
    # existing (v1 golden)
    build_trs2_receipt,
    verify_trs2_receipt,
    TRS2ReceiptError,
    TRS2_SCHEMA_VERSION,
    # new surface under test (does not exist yet -> import fails = AT fails)
    build_trs2_receipt_v2,
    verify_trs2_receipt_v2,
    TRS2_SCHEMA_VERSION_V2,
    RECEIPT_TYPES,
)

H = "a" * 64  # valid lowercase sha256 hex


@pytest.fixture()
def keypair():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


@pytest.fixture()
def sign_fn(keypair):
    priv, _ = keypair
    return lambda digest: priv.sign(digest)


@pytest.fixture()
def event():
    return build_trs2_event(
        source_id="m365-audit",
        source_event_id="evt-0001",
        event_time="2026-08-06T10:00:00Z",
        ingest_time="2026-08-06T10:00:30Z",
        agent_ref="agent://copilot/finance-bot",
        principal_ref="user://alice@example.com",
        action={"category": "data_access", "operation": "read",
                "target_hash": H, "attributes_hash": H},
        outcome={"value": "success"},
    )


GAP_OPEN = {"source_id": "m365-audit",
            "interval_start": "2026-08-06T10:05:00Z"}
GAP_CLOSE = {"source_id": "m365-audit",
             "interval_start": "2026-08-06T10:05:00Z",
             "interval_end": "2026-08-06T10:15:00Z"}


def _v2(sign_fn, **overrides):
    """Build a default valid v2 action receipt; overrides poke at fields."""
    kw = dict(receipt_type="action",
              event=overrides.pop("_event"),
              tenant_id="tenant-1", seq=0, prev_receipt_hash="GENESIS",
              sign_fn=sign_fn, key_id="k1")
    kw.update(overrides)
    return build_trs2_receipt_v2(**kw)


# ---------------------------------------------------------------- constants

def test_version_and_enum_constants():
    assert TRS2_SCHEMA_VERSION_V2 == "receipt_trs2_v2"
    assert RECEIPT_TYPES == frozenset({"action", "gap", "marker"})
    # admin is RESERVED, not present: no speculative enum members.
    assert "admin" not in RECEIPT_TYPES


# ------------------------------------------------------------ v1 golden pin

def test_v1_unchanged_builds_and_verifies(event, sign_fn, keypair):
    _, pub = keypair
    r = build_trs2_receipt(event=event, tenant_id="tenant-1", seq=0,
                           prev_receipt_hash="GENESIS",
                           sign_fn=sign_fn, key_id="k1")
    assert r["schema_version"] == TRS2_SCHEMA_VERSION == "receipt_trs2_v1"
    assert "receipt_type" not in r  # v1 field set is untouched
    verify_trs2_receipt(r, pub)


def test_v1_verifier_rejects_v2_receipt(event, sign_fn, keypair):
    _, pub = keypair
    r = _v2(sign_fn, _event=event)
    # v1's closed field set fires FIRST (unknown field receipt_type),
    # before the schema_version check — the stronger rejection. Either
    # mechanism satisfies the property: v1 refuses v2 receipts.
    with pytest.raises(TRS2ReceiptError,
                       match="receipt_type|schema_version"):
        verify_trs2_receipt(r, pub)


# ---------------------------------------------------------------- v2 action

def test_v2_action_builds_and_verifies(event, sign_fn, keypair):
    _, pub = keypair
    r = _v2(sign_fn, _event=event)
    assert r["schema_version"] == "receipt_trs2_v2"
    assert r["receipt_type"] == "action"
    verify_trs2_receipt_v2(r, pub)


def test_v2_receipt_type_required_at_verify(event, sign_fn, keypair):
    _, pub = keypair
    r = _v2(sign_fn, _event=event)
    del r["receipt_type"]
    with pytest.raises(TRS2ReceiptError, match="receipt_type"):
        verify_trs2_receipt_v2(r, pub)


@pytest.mark.parametrize("bad", ["admin", "ACTION", "", None, 1, "foo"])
def test_v2_enum_rejected_at_build(event, sign_fn, bad):
    with pytest.raises(TRS2ReceiptError, match="receipt_type"):
        _v2(sign_fn, _event=event, receipt_type=bad)


def test_v2_action_with_gap_block_rejected(event, sign_fn):
    with pytest.raises(TRS2ReceiptError):
        _v2(sign_fn, _event=event, gap=GAP_OPEN)


# ------------------------------------------------------------- v2 gap/marker

def test_v2_gap_builds_and_verifies(sign_fn, keypair):
    _, pub = keypair
    r = build_trs2_receipt_v2(receipt_type="gap", gap=dict(GAP_OPEN),
                              tenant_id="tenant-1", seq=1,
                              prev_receipt_hash=H,
                              sign_fn=sign_fn, key_id="k1")
    assert r["receipt_type"] == "gap"
    assert "event" not in r
    verify_trs2_receipt_v2(r, pub)


def test_v2_marker_builds_and_verifies(sign_fn, keypair):
    _, pub = keypair
    r = build_trs2_receipt_v2(receipt_type="marker", gap=dict(GAP_CLOSE),
                              tenant_id="tenant-1", seq=2,
                              prev_receipt_hash=H,
                              sign_fn=sign_fn, key_id="k1")
    verify_trs2_receipt_v2(r, pub)


def test_v2_gap_with_event_rejected(event, sign_fn):
    with pytest.raises(TRS2ReceiptError):
        build_trs2_receipt_v2(receipt_type="gap", gap=dict(GAP_OPEN),
                              event=event,
                              tenant_id="tenant-1", seq=1,
                              prev_receipt_hash=H,
                              sign_fn=sign_fn, key_id="k1")


def test_v2_gap_missing_block_rejected(sign_fn):
    with pytest.raises(TRS2ReceiptError):
        build_trs2_receipt_v2(receipt_type="gap",
                              tenant_id="tenant-1", seq=1,
                              prev_receipt_hash=H,
                              sign_fn=sign_fn, key_id="k1")


def test_v2_marker_requires_interval_end(sign_fn):
    # A marker with the OPEN shape is a schema error: close means closed.
    with pytest.raises(TRS2ReceiptError):
        build_trs2_receipt_v2(receipt_type="marker", gap=dict(GAP_OPEN),
                              tenant_id="tenant-1", seq=2,
                              prev_receipt_hash=H,
                              sign_fn=sign_fn, key_id="k1")


def test_v2_gap_closed_set_rejects_unknown_field(sign_fn):
    poisoned = dict(GAP_OPEN, payload="smuggled")
    with pytest.raises(TRS2ReceiptError):
        build_trs2_receipt_v2(receipt_type="gap", gap=poisoned,
                              tenant_id="tenant-1", seq=1,
                              prev_receipt_hash=H,
                              sign_fn=sign_fn, key_id="k1")


def test_v2_gap_smuggle_after_build_fails_verify(sign_fn, keypair):
    # P11 pattern at the gap block: mutate stored block post-signing.
    _, pub = keypair
    r = build_trs2_receipt_v2(receipt_type="gap", gap=dict(GAP_OPEN),
                              tenant_id="tenant-1", seq=1,
                              prev_receipt_hash=H,
                              sign_fn=sign_fn, key_id="k1")
    r["gap"]["payload"] = "smuggled"
    with pytest.raises(TRS2ReceiptError):
        verify_trs2_receipt_v2(r, pub)


# ------------------------------------------------- receipt_type is SIGNED

def test_receipt_type_relabel_fails_verification(event, sign_fn, keypair):
    """The attack this field exists to survive: relabel a signed action
    receipt as a gap — hide an action as 'source silence'. receipt_type
    is inside the signed body, so the digest no longer matches."""
    _, pub = keypair
    r = _v2(sign_fn, _event=event)
    r["receipt_type"] = "gap"
    del r["event"]
    r["gap"] = dict(GAP_OPEN)
    with pytest.raises(TRS2ReceiptError):
        verify_trs2_receipt_v2(r, pub)
