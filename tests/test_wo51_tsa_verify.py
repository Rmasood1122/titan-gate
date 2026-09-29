"""WO-5.1 AT: offline RFC 3161 timestamp verification (the second leg).

Spec (mirrors anchor_verify's posture — FR-RCP-2 "validate the QTS
against the bundled TSA cert chain, no network"):
  - verify_tsa_token_offline(token_der, *, root_hash_hex, ca_cert_pem)
    validates the token's CMS signature against the provided CA chain
    (no system trust store, no network) AND checks that the timestamped
    message imprint commits to root_hash_hex. A token over a DIFFERENT
    root FAILS even if cryptographically valid — binding, not just
    signature validity.
  - Raises TSAVerificationError on: bad signature, wrong CA, tampered
    token, digest/root mismatch, malformed input.

Fixtures: real freetsa.org token over the PRODUCTION root
4933083c... (already in Rekor, log_index 2239591431). [WIRE]-proven.
"""

from pathlib import Path

import pytest

from titan_gate.tsa_verify import (   # does not exist yet -> RED
    verify_tsa_token_offline,
    TSAVerificationError,
)

TSA = Path(__file__).parent / "fixtures" / "tsa"
ROOT_HEX = "4933083c6ced22f47e00238703dd4a17e02bc5398035601c2ddf03eaf1a9fbbb"


@pytest.fixture()
def token():
    return (TSA / "response.tsr").read_bytes()


@pytest.fixture()
def ca_pem():
    return (TSA / "freetsa_cacert.pem").read_bytes()


# -------------------------------------------------------------- happy path

def test_valid_token_over_correct_root_verifies(token, ca_pem):
    # Returns the timestamp datetime on success (proof it parsed the token).
    ts = verify_tsa_token_offline(token, root_hash_hex=ROOT_HEX,
                                  ca_cert_pem=ca_pem)
    import datetime as _dt
    assert isinstance(ts, _dt.datetime)


def test_verification_uses_no_network(token, ca_pem, monkeypatch):
    import socket
    def _boom(*a, **k):
        raise AssertionError("verification attempted a network connection")
    monkeypatch.setattr(socket, "socket", _boom)
    verify_tsa_token_offline(token, root_hash_hex=ROOT_HEX, ca_cert_pem=ca_pem)


# ------------------------------------------------------------ binding check

def test_token_over_wrong_root_fails(token, ca_pem):
    wrong = "0" * 64
    with pytest.raises(TSAVerificationError):
        verify_tsa_token_offline(token, root_hash_hex=wrong,
                                 ca_cert_pem=ca_pem)


# ------------------------------------------------------------- tamper / trust

def test_tampered_token_fails(token, ca_pem):
    bad = bytearray(token)
    bad[len(bad) // 2] ^= 0xFF   # flip a mid-token byte
    with pytest.raises(TSAVerificationError):
        verify_tsa_token_offline(bytes(bad), root_hash_hex=ROOT_HEX,
                                 ca_cert_pem=ca_pem)


def test_wrong_ca_fails(token):
    # A valid but unrelated CA must not verify this token.
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime as dt
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "not-the-tsa")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime(2020, 1, 1))
            .not_valid_after(dt.datetime(2030, 1, 1))
            .sign(key, hashes.SHA256()))
    wrong_ca = cert.public_bytes(serialization.Encoding.PEM)
    with pytest.raises(TSAVerificationError):
        verify_tsa_token_offline(token, root_hash_hex=ROOT_HEX,
                                 ca_cert_pem=wrong_ca)


def test_malformed_token_fails(ca_pem):
    with pytest.raises(TSAVerificationError):
        verify_tsa_token_offline(b"not a der token", root_hash_hex=ROOT_HEX,
                                 ca_cert_pem=ca_pem)
