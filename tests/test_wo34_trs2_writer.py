"""WO-3.4d AT — TRS-2 receipt writer (build/sign/verify over JCS bytes).

Seam pin: the writer takes an injected sign_fn and holds no key material.
The evidence core requests signatures (V3->C1 pattern); tests simulate
the customer domain by holding a throwaway Ed25519 key HERE, never in
titan_gate/ (Rule 1).

Expected first run: RED (no titan_gate.trs2_writer).
"""
import hashlib
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from titan_gate.canonical import canonical_bytes_jcs
from titan_gate.trs2 import build_trs2_event
from titan_gate.trs2_writer import (
    build_trs2_receipt,
    verify_trs2_receipt,
    TRS2ReceiptError,
    TRS2_SCHEMA_VERSION,
)

# --- customer-domain simulation: key lives in the test, not the core ---
_PRIV = Ed25519PrivateKey.generate()
_PUB = _PRIV.public_key()

def sign_fn(digest_bytes: bytes) -> bytes:
    assert isinstance(digest_bytes, bytes) and len(digest_bytes) == 32
    return _PRIV.sign(digest_bytes)


def make_event(n=1):
    return build_trs2_event(
        source_id="copilot-export-test",
        source_event_id=f"evt-{n:04d}",
        event_time="2026-08-06T12:00:00Z",
        ingest_time="2026-08-06T12:00:41Z",
        agent_ref="agent-42",
        principal_ref="user:test-principal",
        action=dict(category="data_access", operation="read",
                    target_hash="a"*64, attributes_hash="b"*64),
        outcome=dict(value="success"),
    )


def make_receipt(seq=0, prev="GENESIS", n=1):
    return build_trs2_receipt(
        event=make_event(n), tenant_id="tenant-test",
        seq=seq, prev_receipt_hash=prev,
        sign_fn=sign_fn, key_id="test-key-1",
    )


# --- 1. Build + verify round trip ---

def test_build_and_verify_roundtrip():
    r = make_receipt()
    assert r["schema_version"] == TRS2_SCHEMA_VERSION == "receipt_trs2_v1"
    assert r["seq"] == 0
    assert r["prev_receipt_hash"] == "GENESIS"
    assert r["sig"]["alg"] == "ed25519-v1"
    assert r["sig"]["key_id"] == "test-key-1"
    verify_trs2_receipt(r, _PUB)  # raises on failure


def test_digest_is_jcs_of_body_excluding_sig_and_stored_hash():
    r = make_receipt()
    body = {k: v for k, v in r.items() if k not in ("sig", "receipt_hash")}
    expected = hashlib.sha256(canonical_bytes_jcs(body)).hexdigest()
    assert r["receipt_hash"] == expected


def test_signature_is_over_raw_digest_bytes():
    r = make_receipt()
    digest = bytes.fromhex(r["receipt_hash"])
    _PUB.verify(bytes.fromhex(r["sig"]["value"]), digest)  # raises if not


# --- 2. Tamper detection ---

def test_tampered_event_field_fails_verification():
    r = make_receipt()
    r["event"]["outcome"]["value"] = "denied"
    with pytest.raises(TRS2ReceiptError):
        verify_trs2_receipt(r, _PUB)


def test_tampered_prev_hash_fails_verification():
    r = make_receipt()
    r["prev_receipt_hash"] = "c" * 64
    with pytest.raises(TRS2ReceiptError):
        verify_trs2_receipt(r, _PUB)


def test_wrong_public_key_fails_naming_nothing_silently():
    other_pub = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(TRS2ReceiptError):
        verify_trs2_receipt(make_receipt(), other_pub)


# --- 3. Chain linking ---

def test_three_receipt_chain_links_by_receipt_hash():
    r0 = make_receipt(seq=0, prev="GENESIS", n=1)
    r1 = make_receipt(seq=1, prev=r0["receipt_hash"], n=2)
    r2 = make_receipt(seq=2, prev=r1["receipt_hash"], n=3)
    assert r1["prev_receipt_hash"] == r0["receipt_hash"]
    assert r2["prev_receipt_hash"] == r1["receipt_hash"]
    for r in (r0, r1, r2):
        verify_trs2_receipt(r, _PUB)


# --- 4. Closed receipt-level schema; core holds no keys ---

def test_receipt_field_set_is_closed():
    r = make_receipt()
    assert set(r) == {
        "schema_version", "receipt_id", "tenant_id", "seq",
        "prev_receipt_hash", "event", "receipt_hash", "sig",
    }
    assert set(r["sig"]) == {"key_id", "alg", "value"}


def test_verify_rejects_unknown_receipt_field():
    r = make_receipt()
    r["vendor_note"] = "x"
    with pytest.raises(TRS2ReceiptError):
        verify_trs2_receipt(r, _PUB)


def test_writer_module_imports_no_key_material():
    import titan_gate.trs2_writer as w
    src = open(w.__file__, encoding="utf-8").read()
    for forbidden in ("Ed25519PrivateKey", "TITAN_SIGNING_KEY",
                      "private_key", "from api", "import api"):
        assert forbidden not in src, f"core must not contain {forbidden!r}"


# --- 5. P11 regression: verify path must reject top-level event extras ---

def test_verify_rejects_smuggled_toplevel_event_field():
    """probe_24 P11: a receipt with an unknown TOP-LEVEL event field,
    validly re-hashed and re-signed, must FAIL verification. The build
    path rejects this; the verify path cherry-picked known fields and
    let it through. Rebuilt-equals-stored closes it."""
    import hashlib
    from titan_gate.canonical import canonical_bytes_jcs
    r = make_receipt()
    r["event"]["smuggled_payload"] = "exfiltrated content"
    body = {k: v for k, v in r.items() if k not in ("sig", "receipt_hash")}
    r["receipt_hash"] = hashlib.sha256(canonical_bytes_jcs(body)).hexdigest()
    r["sig"]["value"] = _PRIV.sign(bytes.fromhex(r["receipt_hash"])).hex()
    with pytest.raises(TRS2ReceiptError):
        verify_trs2_receipt(r, _PUB)
