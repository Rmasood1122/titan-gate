"""WO-4.3 part 2a AT — anchor writer: sign (prehashed, via seam) ->
submit -> persist record; on failure persist disclosure and proceed.

Pins:
  1. Success: anchor_<root16>.json written, closed schema, and it
     VERIFIES offline via verify_anchor_record_offline against the
     pinned production key (mocked response = the LIVE fixture, so
     this is a real end-to-end offline verification).
  2. sign_fn receives the RAW 32 digest bytes (prehashed contract,
     wire-proven in 4.2b); module holds no keys (lint).
  3. Failure (Rekor unreachable/HTTP error): anchor_status.json
     written {attempted, ok:false, error, root_hash, timestamp};
     function RETURNS degraded status, does not raise — proceeding
     unanchored-but-disclosed IS the FR-RCP-2 shape at one leg.
  4. Success after prior failure replaces the status file (recovery
     is visible, stale failure disclosures don't linger).

Expected first run: RED (no titan_gate.anchor_writer).
"""
import base64
import hashlib
import json
import os
import pytest
from unittest import mock
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

from titan_gate.anchor_writer import anchor_root, AnchorWriteStatus
from titan_gate.anchor_verify import verify_anchor_record_offline

FIX = os.path.join(os.path.dirname(__file__), "fixtures")

# The live probe's artifact hash — what the fixture entry actually covers
LIVE_ROOT_HEX = hashlib.sha256(b"titan-gate-wo42b-live-probe").hexdigest()

_PRIV = ec.generate_private_key(ec.SECP256R1())
_PEM = _PRIV.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo).decode()

SIGN_CALLS = []
def sign_fn(digest: bytes) -> bytes:
    SIGN_CALLS.append(digest)
    return _PRIV.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

def _fixture_response():
    with open(os.path.join(FIX, "live_anchor_entry.json"), encoding="utf-8") as f:
        return json.load(f)

def _mock_ok(payload):
    m = mock.MagicMock()
    m.read.return_value = json.dumps(payload).encode()
    m.__enter__ = lambda s: s
    m.__exit__ = mock.MagicMock(return_value=False)
    return m


def test_success_persists_record_that_verifies_offline(tmp_path):
    SIGN_CALLS.clear()
    with mock.patch("titan_gate.rekor_client.urlopen",
                    return_value=_mock_ok(_fixture_response())):
        status = anchor_root(root_hash_hex=LIVE_ROOT_HEX, sign_fn=sign_fn,
                             public_key_pem=_PEM,
                             base_url="https://rekor.example",
                             out_dir=str(tmp_path))
    assert isinstance(status, AnchorWriteStatus)
    assert status.ok is True
    path = tmp_path / f"anchor_{LIVE_ROOT_HEX[:16]}.json"
    assert path.exists()
    rec = json.loads(path.read_text(encoding="utf-8"))
    with open(os.path.join(FIX, "rekor_log_pubkey.pem"), "rb") as f:
        log_pub = serialization.load_pem_public_key(f.read())
    verify_anchor_record_offline(rec, log_pub,
                                 expected_artifact_hash_hex=LIVE_ROOT_HEX)
    assert not (tmp_path / "anchor_status.json").exists() or \
        json.loads((tmp_path / "anchor_status.json").read_text(
            encoding="utf-8"))["ok"] is True


def test_sign_fn_receives_raw_digest_prehashed_contract(tmp_path):
    SIGN_CALLS.clear()
    with mock.patch("titan_gate.rekor_client.urlopen",
                    return_value=_mock_ok(_fixture_response())):
        anchor_root(root_hash_hex=LIVE_ROOT_HEX, sign_fn=sign_fn,
                    public_key_pem=_PEM, base_url="https://r.example",
                    out_dir=str(tmp_path))
    assert len(SIGN_CALLS) == 1
    assert SIGN_CALLS[0] == bytes.fromhex(LIVE_ROOT_HEX)  # raw digest, 32B


def test_writer_module_holds_no_keys():
    import titan_gate.anchor_writer as w
    src = open(w.__file__, encoding="utf-8").read()
    for forbidden in ("Ed25519PrivateKey", "generate_private_key",
                      "TITAN_SIGNING_KEY", "from api", "import api"):
        assert forbidden not in src, f"writer must not contain {forbidden!r}"


def test_failure_writes_disclosure_and_returns_degraded(tmp_path):
    import urllib.error
    err = urllib.error.URLError("connection refused")
    with mock.patch("titan_gate.rekor_client.urlopen", side_effect=err):
        status = anchor_root(root_hash_hex=LIVE_ROOT_HEX, sign_fn=sign_fn,
                             public_key_pem=_PEM,
                             base_url="https://rekor.example",
                             out_dir=str(tmp_path))
    assert status.ok is False
    assert "refused" in status.error or "unreachable" in status.error
    s = json.loads((tmp_path / "anchor_status.json").read_text(encoding="utf-8"))
    assert s["ok"] is False and s["attempted"] is True
    assert s["root_hash"] == LIVE_ROOT_HEX
    assert s["error"] and s["timestamp"]
    assert not (tmp_path / f"anchor_{LIVE_ROOT_HEX[:16]}.json").exists()


def test_recovery_replaces_stale_failure_disclosure(tmp_path):
    import urllib.error
    with mock.patch("titan_gate.rekor_client.urlopen",
                    side_effect=urllib.error.URLError("down")):
        anchor_root(root_hash_hex=LIVE_ROOT_HEX, sign_fn=sign_fn,
                    public_key_pem=_PEM, base_url="https://r.example",
                    out_dir=str(tmp_path))
    assert json.loads((tmp_path / "anchor_status.json").read_text(
        encoding="utf-8"))["ok"] is False
    with mock.patch("titan_gate.rekor_client.urlopen",
                    return_value=_mock_ok(_fixture_response())):
        status = anchor_root(root_hash_hex=LIVE_ROOT_HEX, sign_fn=sign_fn,
                             public_key_pem=_PEM, base_url="https://r.example",
                             out_dir=str(tmp_path))
    assert status.ok is True
    assert json.loads((tmp_path / "anchor_status.json").read_text(
        encoding="utf-8"))["ok"] is True
    assert (tmp_path / f"anchor_{LIVE_ROOT_HEX[:16]}.json").exists()


def test_bad_root_hash_raises_not_discloses(tmp_path):
    """Malformed INPUT is a caller bug -> raise. Only EXTERNAL failure
    (network/HTTP) degrades to disclosure."""
    with pytest.raises(Exception):
        anchor_root(root_hash_hex="not-hex", sign_fn=sign_fn,
                    public_key_pem=_PEM, base_url="https://r.example",
                    out_dir=str(tmp_path))
    assert not (tmp_path / "anchor_status.json").exists()
