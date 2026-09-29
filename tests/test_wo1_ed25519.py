"""WO-1 acceptance tests — Ed25519 asymmetric receipt signing (TRS-2, ed25519-v1).

Run BEFORE adding api/signers.py to prove RED (collection error = expected failure),
then add api/signers.py and re-run for GREEN.

Acceptance criteria (MASTER_STATE §4 WO-1):
  1. New receipts verify with the PUBLIC key only — no secret required to verify.
  2. A tampered receipt FAILS verification.
  3. Verification with the wrong public key FAILS.
  4. signing_version is bound inside the signed body (downgrade attempts fail).
  5. Legacy HMAC path remains importable/verifiable (compat flag) — skipped if absent.
"""
import sys
import os
import pytest

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "api"))

from api.signers import (  # noqa: E402  (RED: this import fails until signers.py exists)
    Ed25519Signer,
    generate_keypair,
    verify_ed25519,
    VerificationError,
    SIGNING_V2_ED25519,
)


def sample_receipt():
    return {
        "receipt_id": "wo1-test-001",
        "tenant_id": "tenant_test",
        "action": {"category": "tool_call", "operation": "deploy"},
        "decision": "ALLOW",
        "actor": "agent-x",
        "prev_receipt_hash": "GENESIS",
    }


def test_keygen_produces_distinct_hex_keys():
    priv, pub = generate_keypair()
    assert len(priv) == 64 and len(pub) == 64  # 32 raw bytes hex-encoded
    assert priv != pub
    priv2, pub2 = generate_keypair()
    assert (priv, pub) != (priv2, pub2)


def test_sign_then_verify_with_public_key_only():
    priv, pub = generate_keypair()
    signed = Ed25519Signer(priv).sign(sample_receipt())
    assert signed["signing_version"] == SIGNING_V2_ED25519
    assert "signature" in signed and len(signed["signature"]) == 128
    # THE acceptance criterion: verification takes ONLY the public key.
    assert verify_ed25519(signed, pub) is True


def test_tampered_receipt_fails():
    priv, pub = generate_keypair()
    signed = Ed25519Signer(priv).sign(sample_receipt())
    signed["decision"] = "DENY"  # the ARE P24 tamper, replayed here
    with pytest.raises(VerificationError):
        verify_ed25519(signed, pub)


def test_wrong_public_key_fails():
    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    signed = Ed25519Signer(priv).sign(sample_receipt())
    with pytest.raises(VerificationError):
        verify_ed25519(signed, other_pub)


def test_signature_field_excluded_from_signed_body():
    """Signing must be stable: signing a receipt twice yields identical signatures,
    proving the signature field itself is excluded from canonical bytes."""
    priv, pub = generate_keypair()
    s1 = Ed25519Signer(priv).sign(sample_receipt())
    s2 = Ed25519Signer(priv).sign(sample_receipt())
    assert s1["signature"] == s2["signature"]
    assert verify_ed25519(s1, pub)


def test_signing_version_is_downgrade_protected():
    """signing_version sits INSIDE the hashed body: rewriting it post-hoc must fail."""
    priv, pub = generate_keypair()
    signed = Ed25519Signer(priv).sign(sample_receipt())
    signed["signing_version"] = "hmac-sha256-v1"  # downgrade attempt
    with pytest.raises(VerificationError):
        verify_ed25519(signed, pub)


def test_legacy_hmac_path_still_present():
    """Compat: the existing HMAC implementation must remain importable so old
    receipts stay verifiable under the legacy flag. Skips if module layout differs."""
    try:
        from api import receipt_signing as legacy  # noqa: F401
    except ImportError:
        pytest.skip("legacy module not importable from this layout")
    assert hasattr(legacy, "canonical_bytes")
