"""WO-4.3 AT (part 1) — offline verification of a REAL Rekor anchor
record: the live entry from 2026-08-07 (uuid 108e9186..., log_index
2238835089), fetched and committed as fixture.

This is FRD AT-16's first half against production data, not a
synthetic tree: leaf = sha256(0x00 || entry_body_bytes), walk the
24-hash proof to the checkpoint root, verify the checkpoint's ECDSA
signature against the PINNED log key. Zero network in any test here.

Composes only existing proven pieces (rekor_inclusion 6962 math +
checkpoint parsing/ECDSA + rekor_client anchor record) behind ONE
function: verify_anchor_record_offline. New failure surface pinned:
  - proof/checkpoint incoherence (equivocation-at-record-scale,
    TDD Narrative E) must FAIL even if each half is self-consistent
  - body-bytes question answered by the wire: if the leaf recompute
    walks to the root, entry body verbatim IS the leaf content [F]

Expected first run: RED (no titan_gate.anchor_verify).
"""
import base64
import json
import os
import pytest
from cryptography.hazmat.primitives import serialization

from titan_gate.rekor_client import parse_entry_to_anchor_record
from titan_gate.anchor_verify import (
    verify_anchor_record_offline,
    AnchorVerificationError,
)

FIX = os.path.join(os.path.dirname(__file__), "fixtures")

@pytest.fixture(scope="module")
def anchor_record():
    # encoding MANDATORY: bare open() on Windows is cp1252 and
    # mojibakes the checkpoint's em dash (third encoding bug today)
    with open(os.path.join(FIX, "live_anchor_entry.json"), encoding="utf-8") as f:
        return parse_entry_to_anchor_record(json.load(f))

@pytest.fixture(scope="module")
def log_pubkey():
    with open(os.path.join(FIX, "rekor_log_pubkey.pem"), "rb") as f:
        return serialization.load_pem_public_key(f.read())


# --- 1. The real thing verifies, offline ---

def test_live_anchor_verifies_offline(anchor_record, log_pubkey):
    verify_anchor_record_offline(anchor_record, log_pubkey)  # raises on failure

def test_expected_artifact_hash_binding(anchor_record, log_pubkey):
    """Caller can require the anchor to cover a SPECIFIC artifact hash
    (the interval root we sealed). The live probe's artifact:
    sha256(b'titan-gate-wo42b-live-probe')."""
    import hashlib
    expected = hashlib.sha256(b"titan-gate-wo42b-live-probe").hexdigest()
    verify_anchor_record_offline(anchor_record, log_pubkey,
                                 expected_artifact_hash_hex=expected)

def test_wrong_expected_artifact_hash_fails(anchor_record, log_pubkey):
    with pytest.raises(AnchorVerificationError):
        verify_anchor_record_offline(anchor_record, log_pubkey,
                                     expected_artifact_hash_hex="f" * 64)


# --- 2. Adversarial mutations of a REAL record all fail ---

def _mut(rec, **changes):
    r = json.loads(json.dumps(rec))
    r.update(changes)
    return r

def test_tampered_entry_body_fails(anchor_record, log_pubkey):
    body = base64.b64decode(anchor_record["entry_body_b64"])
    tampered = base64.b64encode(body.replace(b"sha256", b"sha255")).decode()
    with pytest.raises(AnchorVerificationError):
        verify_anchor_record_offline(
            _mut(anchor_record, entry_body_b64=tampered), log_pubkey)

def test_mutated_proof_hash_fails(anchor_record, log_pubkey):
    hashes = list(anchor_record["hashes"]); hashes[10] = "0" * 64
    with pytest.raises(AnchorVerificationError):
        verify_anchor_record_offline(
            _mut(anchor_record, hashes=hashes), log_pubkey)

def test_wrong_log_index_fails(anchor_record, log_pubkey):
    with pytest.raises(AnchorVerificationError):
        verify_anchor_record_offline(
            _mut(anchor_record, log_index=anchor_record["log_index"] + 1),
            log_pubkey)

def test_tampered_checkpoint_fails(anchor_record, log_pubkey):
    cp = anchor_record["checkpoint_raw"].replace(
        str(anchor_record["tree_size"]), str(anchor_record["tree_size"] + 1), 1)
    with pytest.raises(AnchorVerificationError):
        verify_anchor_record_offline(
            _mut(anchor_record, checkpoint_raw=cp), log_pubkey)

def test_wrong_pinned_key_fails(anchor_record):
    from cryptography.hazmat.primitives.asymmetric import ec
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(AnchorVerificationError):
        verify_anchor_record_offline(anchor_record, other)


# --- 3. Record-scale equivocation: halves must AGREE, not just self-verify ---

def test_checkpoint_proof_root_mismatch_fails(anchor_record, log_pubkey):
    """A record whose stored root_hash disagrees with its checkpoint's
    root must FAIL before any signature math — mismatched pairs are the
    equivocation shape (TDD Narrative E) at record scale."""
    with pytest.raises(AnchorVerificationError):
        verify_anchor_record_offline(
            _mut(anchor_record, root_hash="9" * 64), log_pubkey)

def test_checkpoint_size_mismatch_fails(anchor_record, log_pubkey):
    with pytest.raises(AnchorVerificationError):
        verify_anchor_record_offline(
            _mut(anchor_record, tree_size=anchor_record["tree_size"] - 1),
            log_pubkey)
