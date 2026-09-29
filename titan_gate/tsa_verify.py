"""Offline RFC 3161 timestamp verification — the second anchor leg (WO-5).

Mirrors anchor_verify's posture (FR-RCP-2): validate the token against an
EXPLICIT CA chain — no system trust store, no network — AND bind it to
our Merkle root. A token valid over a DIFFERENT digest FAILS: binding,
not mere signature checking.

TG-12 (fail-open dependency): rfc3161-client's verify() checks the
token's INTERNAL consistency (embedded leaf signs the imprint) but does
NOT enforce that the signer chains to a caller-supplied root — it returns
True against a wrong CA. A verification path that ignores the caller's
trust anchor is the ARE /verify fail-open class. So trust-anchoring is
OURS: we walk leaf -> root by issuer name, cryptographically verifying
each hop, and require the supplied root's key to actually sign the chain,
BEFORE trusting the token. Caught by test_wrong_ca_fails.

The message-imprint hash algorithm is read FROM the token (self-
describing), so an eIDAS QTSP using a different algorithm is a drop-in
swap, not a code change.
"""

import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from rfc3161_client import decode_timestamp_response, VerifierBuilder
from rfc3161_client.errors import VerificationError as _RFCVerificationError

__all__ = ["verify_tsa_token_offline", "TSAVerificationError"]

_OID_TO_HASH = {
    "2.16.840.1.101.3.4.2.1": hashlib.sha256,
    "2.16.840.1.101.3.4.2.2": hashlib.sha384,
    "2.16.840.1.101.3.4.2.3": hashlib.sha512,
}


class TSAVerificationError(ValueError):
    """Timestamp token failed offline verification, chain, or root binding."""


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _verify_issuer_signature(child: x509.Certificate,
                             issuer: x509.Certificate) -> None:
    """Raise InvalidSignature (or TSAVerificationError) unless issuer's
    key signed child's tbs bytes."""
    pub = issuer.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   padding.PKCS1v15(), child.signature_hash_algorithm)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   ECDSA(child.signature_hash_algorithm))
    else:
        raise TSAVerificationError(
            f"unsupported issuer key type {type(pub).__name__}")


def _chains_to_root(certs, root: x509.Certificate) -> bool:
    """Walk embedded leaf -> ... -> a cert signed by root, verifying each
    hop's signature. Fail-closed: an unreachable or non-signing root
    returns False. This is OUR trust anchor (see TG-12)."""
    leaves = [c for c in certs if not _is_ca(c)]
    if not leaves:
        return False
    pool = {c.subject.rfc4514_string(): c for c in certs}
    cur = leaves[0]
    root_name = root.subject.rfc4514_string()
    for _ in range(len(certs) + 2):  # bounded: no cycles
        if cur.issuer.rfc4514_string() == root_name:
            try:
                _verify_issuer_signature(cur, root)
            except InvalidSignature:
                return False
            return True
        nxt = pool.get(cur.issuer.rfc4514_string())
        if nxt is None:
            return False
        try:
            _verify_issuer_signature(cur, nxt)
        except InvalidSignature:
            return False
        cur = nxt
    return False


def verify_tsa_token_offline(token_der: bytes, *, root_hash_hex: str,
                             ca_cert_pem: bytes):
    """Verify a DER timestamp token offline against ca_cert_pem, bound to
    root_hash_hex. Returns the timestamp datetime on success; raises
    TSAVerificationError on any failure. No network, no system trust."""
    if not isinstance(token_der, (bytes, bytearray)):
        raise TSAVerificationError(
            f"token must be bytes, got {type(token_der).__name__}")
    try:
        root_bytes = bytes.fromhex(root_hash_hex)
    except (ValueError, TypeError) as e:
        raise TSAVerificationError(f"root_hash_hex not hex: {e}") from e
    try:
        resp = decode_timestamp_response(bytes(token_der))
    except Exception as e:  # noqa: BLE001 — any decode failure = bad token
        raise TSAVerificationError(f"undecodable token: {e}") from e
    try:
        ca = x509.load_pem_x509_certificate(ca_cert_pem)
    except (ValueError, TypeError) as e:
        raise TSAVerificationError(f"invalid CA cert PEM: {e}") from e
    try:
        certs = [x509.load_der_x509_certificate(c)
                 for c in resp.signed_data.certificates]
    except Exception as e:  # noqa: BLE001
        raise TSAVerificationError(f"unreadable embedded certs: {e}") from e

    # (1) TRUST ANCHOR — ours, because the library doesn't enforce it (TG-12).
    if not _chains_to_root(certs, ca):
        raise TSAVerificationError(
            "token signer does not chain to the supplied root CA "
            "(fail-closed trust anchor — TG-12)")

    # (2) Hash root with the algorithm the TOKEN declares (self-describing).
    oid = resp.tst_info.message_imprint.hash_algorithm.dotted_string
    hasher = _OID_TO_HASH.get(oid)
    if hasher is None:
        raise TSAVerificationError(
            f"unsupported message-imprint hash OID {oid!r} — no hardcoded "
            f"fallback by design; add it to _OID_TO_HASH deliberately")
    hashed_root = hasher(root_bytes).digest()

    # (3) TOKEN STRUCTURE + IMPRINT BINDING — library's job. A token over a
    # DIFFERENT digest raises "Mismatch between messages".
    builder = VerifierBuilder().add_root_certificate(ca)
    for inter in (c for c in certs if _is_ca(c) and c != ca):
        builder = builder.add_intermediate_certificate(inter)
    try:
        ok = builder.build().verify(resp, hashed_root)
    except _RFCVerificationError as e:
        raise TSAVerificationError(
            f"timestamp verification failed: {e}") from e
    if not ok:
        raise TSAVerificationError("timestamp verification returned false")

    return resp.tst_info.gen_time
