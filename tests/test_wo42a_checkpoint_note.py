"""WO-4.2a AT — Rekor signed-note (checkpoint) parsing + ECDSA P-256
checkpoint verification.

DISCOVERY (from live rekor.sigstore.dev STH, captured 2026-08-07): the
production log signs checkpoints with ECDSA P-256 (DER sigs, 0x3045...
after the 4-byte key hint) — NOT Ed25519. WO-4.1's checkpoint check was
synthetic-key mechanics; this closes the gap against the real format.

Note format (sumdb signed note):
  <origin>\n<tree_size>\n<base64 root>\n[optional extra lines]\n
  \n
  \u2014 <name> <base64(4-byte keyhint || signature)>\n
Body = everything through the blank line (inclusive of its \n).

Expected first run: RED (no parse_checkpoint_note / verify_checkpoint_ecdsa).
"""
import base64
import hashlib
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from titan_gate.rekor_inclusion import (
    parse_checkpoint_note,
    verify_checkpoint_ecdsa,
    RekorVerificationError,
)

# --- synthetic P-256 log for round-trip tests ---
_LOG_PRIV = ec.generate_private_key(ec.SECP256R1())
_LOG_PUB = _LOG_PRIV.public_key()

def _make_note(origin="test.log - 12345", size=8, root=b"\x42" * 32,
               name="test.log"):
    body = (f"{origin}\n{size}\n".encode()
            + base64.b64encode(root) + b"\n")
    sig = _LOG_PRIV.sign(body, ec.ECDSA(hashes.SHA256()))
    hint = b"\xc0\xd2\x3d\x6a"  # arbitrary 4-byte hint for tests
    sig_line = ("\u2014 " + name + " ").encode() \
        + base64.b64encode(hint + sig) + b"\n"
    return body + b"\n" + sig_line, body, sig, hint


# --- 1. Parsing: synthetic round-trip ---

def test_parse_splits_body_and_signature():
    note, body, sig, hint = _make_note()
    parsed_body, sigs = parse_checkpoint_note(note)
    assert parsed_body == body
    assert len(sigs) == 1
    name, parsed_hint, parsed_sig = sigs[0]
    assert name == "test.log"
    assert parsed_hint == hint
    assert parsed_sig == sig


def test_parse_real_rekor_sth_fixture():
    """REAL bytes from rekor.sigstore.dev /api/v1/log, 2026-08-07.
    Parsing only — signature verification against the real log key is
    the pinned-key wiring in WO-4.3."""
    raw = ("rekor.sigstore.dev - 1193050959916656506\n"
           "2238640372\n"
           "gReXIrHBl28/o9l6YLwlE7bswfQUoHWvjIQdbpRwl1o=\n"
           "\n"
           "\u2014 rekor.sigstore.dev wNI9ajBFAiEAzigxFpBj9UlFTu225U26"
           "xCNa/YZ2XpcJWPP7H60RJ1oCIC5Vcd75qtC2lxhgz09sqtLkqXPZBcXEZ"
           "PBrDYWNm6ws\n").encode()
    body, sigs = parse_checkpoint_note(raw)
    assert body.endswith(b"gReXIrHBl28/o9l6YLwlE7bswfQUoHWvjIQdbpRwl1o=\n")
    assert b"2238640372" in body
    name, hint, sig = sigs[0]
    assert name == "rekor.sigstore.dev"
    assert len(hint) == 4
    assert sig[0] == 0x30  # DER SEQUENCE: ECDSA, the discovery this AT pins


@pytest.mark.parametrize("mutation", [
    lambda n: n.replace(b"\n\n", b"\n"),          # missing separator
    lambda n: n.split(b"\n\n")[0] + b"\n\n",       # no signature lines
    lambda n: n.replace(b"wNI", b"!!!") if b"wNI" in n else
              n[:-20] + b"@@@bad-base64@@@\n",     # corrupt base64
])
def test_malformed_notes_rejected(mutation):
    note, *_ = _make_note()
    with pytest.raises(RekorVerificationError):
        parse_checkpoint_note(mutation(note))


def test_signature_shorter_than_hint_rejected():
    note, body, _, _ = _make_note()
    bad = body + b"\n" + "\u2014 test.log ".encode() \
        + base64.b64encode(b"\x01\x02\x03") + b"\n"
    with pytest.raises(RekorVerificationError):
        parse_checkpoint_note(bad)


# --- 2. ECDSA checkpoint verification ---

def test_ecdsa_checkpoint_verifies():
    note, body, sig, _ = _make_note()
    verify_checkpoint_ecdsa(body, sig, _LOG_PUB)  # raises on failure


def test_ecdsa_tampered_body_fails():
    note, body, sig, _ = _make_note()
    tampered = body.replace(b"\n8\n", b"\n9\n")
    assert tampered != body
    with pytest.raises(RekorVerificationError):
        verify_checkpoint_ecdsa(tampered, sig, _LOG_PUB)


def test_ecdsa_wrong_key_fails():
    note, body, sig, _ = _make_note()
    other = ec.generate_private_key(ec.SECP256R1()).public_key()
    with pytest.raises(RekorVerificationError):
        verify_checkpoint_ecdsa(body, sig, other)


def test_ecdsa_garbage_der_fails():
    _, body, _, _ = _make_note()
    with pytest.raises(RekorVerificationError):
        verify_checkpoint_ecdsa(body, b"\x30\x45" + b"\x00" * 69, _LOG_PUB)


# --- 3. End-to-end: parse then verify ---

def test_parse_then_verify_roundtrip():
    note, _, _, _ = _make_note(size=2238640372,
                               root=hashlib.sha256(b"x").digest())
    body, sigs = parse_checkpoint_note(note)
    _, _, sig = sigs[0]
    verify_checkpoint_ecdsa(body, sig, _LOG_PUB)
