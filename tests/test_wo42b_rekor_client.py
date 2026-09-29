"""WO-4.2b AT — Rekor submission client + anchor record.

Pins:
  1. submit_hashedrekord builds the documented hashedrekord proposal,
     POSTs it (stdlib urllib, mocked here), NEVER signs (signature is
     an argument — sign_fn seam upstream, Rule 1).
  2. parse_entry_to_anchor_record extracts a CLOSED-schema anchor
     record; checkpoint stored VERBATIM (bytes for later
     parse_checkpoint_note); entry body kept (the log's leaf is the
     entry body hash, not the artifact hash — without it, offline
     inclusion verification has no leaf to recompute).
  3. Fixture shapes are [V from Rekor API docs] until the live opt-in
     test (TITAN_LIVE_REKOR=1) upgrades them to [F]. That run is part
     of 4.2b's definition of done.

Expected first run: RED (no titan_gate.rekor_client).
"""
import base64
import json
import os
import pytest
from unittest import mock

from titan_gate.rekor_client import (
    build_hashedrekord_proposal,
    submit_hashedrekord,
    parse_entry_to_anchor_record,
    RekorClientError,
    ANCHOR_RECORD_FIELDS,
)

ROOT_HEX = "a" * 64
SIG_B64 = base64.b64encode(b"\x30\x45" + b"\x01" * 69).decode()
PUB_PEM = "-----BEGIN PUBLIC KEY-----\nMFkw...test...\n-----END PUBLIC KEY-----\n"

# Canned response per Rekor OpenAPI: {uuid: {body, integratedTime,
# logID, logIndex, verification: {inclusionProof: {checkpoint, hashes,
# logIndex, rootHash, treeSize}, signedEntryTimestamp}}}
FIXTURE_UUID = "24296fb24b8ad77a" + "b" * 48
FIXTURE = {
    FIXTURE_UUID: {
        "body": base64.b64encode(json.dumps(
            {"apiVersion": "0.0.1", "kind": "hashedrekord",
             "spec": {"data": {"hash": {"algorithm": "sha256",
                                        "value": ROOT_HEX}}}}).encode()).decode(),
        "integratedTime": 1754558400,
        "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
        "logIndex": 512345678,
        "verification": {
            "inclusionProof": {
                "checkpoint": ("rekor.sigstore.dev - 1193050959916656506\n"
                               "2238640372\n"
                               "gReXIrHBl28/o9l6YLwlE7bswfQUoHWvjIQdbpRwl1o=\n"
                               "\n"
                               "\u2014 rekor.sigstore.dev wNI9ajBFAiEA...fixture\n"),
                "hashes": ["c" * 64, "d" * 64, "e" * 64],
                "logIndex": 512345678,
                "rootHash": "81179722b1c1976f3fa3d97a60bc2513b6ecc1f414a075af8c841d6e9470975a",
                "treeSize": 2238640372,
            },
            "signedEntryTimestamp": "MEUCIQ...fixture",
        },
    }
}


# --- 1. Proposal construction (no network) ---

def test_proposal_shape_is_documented_hashedrekord():
    p = build_hashedrekord_proposal(
        artifact_hash_hex=ROOT_HEX, signature_b64=SIG_B64, public_key_pem=PUB_PEM)
    assert p["kind"] == "hashedrekord"
    assert p["apiVersion"] == "0.0.1"
    assert p["spec"]["data"]["hash"] == {"algorithm": "sha256", "value": ROOT_HEX}
    assert p["spec"]["signature"]["content"] == SIG_B64
    pk = p["spec"]["signature"]["publicKey"]["content"]
    assert base64.b64decode(pk).decode() == PUB_PEM  # PEM travels base64ed


def test_proposal_rejects_bad_hash():
    with pytest.raises(RekorClientError):
        build_hashedrekord_proposal(
            artifact_hash_hex="XYZ", signature_b64=SIG_B64, public_key_pem=PUB_PEM)


def test_client_module_never_signs():
    import titan_gate.rekor_client as c
    src = open(c.__file__, encoding="utf-8").read()
    for forbidden in ("Ed25519PrivateKey", "TITAN_SIGNING_KEY", "private_key",
                      ".sign(", "from api", "import api"):
        assert forbidden not in src, f"client must not contain {forbidden!r}"


# --- 2. Submission (urllib mocked) ---

def _mock_response(payload, code=201):
    m = mock.MagicMock()
    m.read.return_value = json.dumps(payload).encode()
    m.status = code
    m.__enter__ = lambda s: s
    m.__exit__ = mock.MagicMock(return_value=False)
    return m

def test_submit_posts_and_returns_entry():
    with mock.patch("titan_gate.rekor_client.urlopen",
                    return_value=_mock_response(FIXTURE)) as u:
        entry = submit_hashedrekord(
            artifact_hash_hex=ROOT_HEX, signature_b64=SIG_B64,
            public_key_pem=PUB_PEM, base_url="https://rekor.example")
    req = u.call_args[0][0]
    assert req.full_url == "https://rekor.example/api/v1/log/entries"
    assert req.get_header("Content-type") == "application/json"
    sent = json.loads(req.data)
    assert sent["kind"] == "hashedrekord"
    assert FIXTURE_UUID in entry

def test_submit_http_error_raises():
    import urllib.error
    err = urllib.error.HTTPError("u", 409, "Conflict", {}, None)
    with mock.patch("titan_gate.rekor_client.urlopen", side_effect=err):
        with pytest.raises(RekorClientError):
            submit_hashedrekord(artifact_hash_hex=ROOT_HEX, signature_b64=SIG_B64,
                                public_key_pem=PUB_PEM, base_url="https://r.example")


# --- 3. Anchor record: closed schema, verbatim checkpoint, leaf kept ---

def test_anchor_record_closed_schema():
    rec = parse_entry_to_anchor_record(FIXTURE)
    assert set(rec) == ANCHOR_RECORD_FIELDS == frozenset({
        "anchor_version", "uuid", "log_index", "tree_size", "root_hash",
        "hashes", "checkpoint_raw", "entry_body_b64", "integrated_time",
    })
    assert rec["anchor_version"] == "rekor_v1"
    assert rec["uuid"] == FIXTURE_UUID
    assert rec["log_index"] == 512345678
    assert rec["tree_size"] == 2238640372

def test_checkpoint_stored_verbatim_and_body_kept():
    rec = parse_entry_to_anchor_record(FIXTURE)
    assert rec["checkpoint_raw"] == \
        FIXTURE[FIXTURE_UUID]["verification"]["inclusionProof"]["checkpoint"]
    body = json.loads(base64.b64decode(rec["entry_body_b64"]))
    assert body["spec"]["data"]["hash"]["value"] == ROOT_HEX

def test_multi_entry_response_rejected():
    two = dict(FIXTURE); two["f" * 64] = FIXTURE[FIXTURE_UUID]
    with pytest.raises(RekorClientError):
        parse_entry_to_anchor_record(two)

def test_missing_inclusion_proof_rejected():
    broken = json.loads(json.dumps(FIXTURE))
    del broken[FIXTURE_UUID]["verification"]["inclusionProof"]
    with pytest.raises(RekorClientError):
        parse_entry_to_anchor_record(broken)


# --- 4. Live round-trip (deliberate, never CI) ---

@pytest.mark.skipif(not os.environ.get("TITAN_LIVE_REKOR"),
                    reason="live Rekor submission: set TITAN_LIVE_REKOR=1")
def test_live_submission_roundtrip():
    """Upgrades fixture shapes from [V-docs] to [F-wire]. Submits one
    real hashedrekord for a throwaway hash under a throwaway key.
    Run once, deliberately, from the founder's machine."""
    import hashlib
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes, serialization
    priv = ec.generate_private_key(ec.SECP256R1())
    artifact = hashlib.sha256(b"titan-gate-wo42b-live-probe").digest()
    # Prehashed: artifact IS the digest. Signing it with plain
    # ECDSA(SHA256) double-hashes and Rekor rejects (HTTP 400,
    # confirmed live 2026-08-07). [F] for WO-4.3: the sign_fn seam's
    # anchoring path signs the raw digest prehashed — same contract
    # as receipt signing (sign the 32 digest bytes).
    sig = priv.sign(artifact, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    entry = submit_hashedrekord(
        artifact_hash_hex=artifact.hex(),
        signature_b64=base64.b64encode(sig).decode(),
        public_key_pem=pem, base_url="https://rekor.sigstore.dev")
    rec = parse_entry_to_anchor_record(entry)
    assert rec["anchor_version"] == "rekor_v1"
    print(f"\nLIVE ANCHOR: uuid={rec['uuid']} log_index={rec['log_index']}")
