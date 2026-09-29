"""Offline RFC 6962 inclusion-proof and checkpoint-signature verification
for Rekor anchors (WO-4.1; FRD AT-16 first half).

Domain separation note (load-bearing): RFC 6962 hashing is
  leaf = SHA-256(0x00 || data)
  node = SHA-256(0x01 || left || right)
This is REKOR'S convention, distinct from Titan's own 'L|'-prefixed
Merkle tree. Two trees, two conventions; this module implements 6962
and must never share code with titan's merkle module — the domain
prefixes are the defense against node-as-leaf second-preimage forgery,
and mixing conventions would silently void it.

Verification here is pure math + one Ed25519 check: no network, no
sigstore machinery, no dependency beyond `cryptography` (already the
verifier's only dependency). Checkpoint signed-note FORMAT parsing
(base64 signature lines, key hints) lives in the anchor-record layer
(WO-4.2), which hands this module raw bytes.
"""
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = [
    "verify_inclusion_proof",
    "verify_checkpoint_signature",
    "RekorVerificationError",
]


class RekorVerificationError(ValueError):
    """Inclusion proof or checkpoint signature failed verification."""


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion_proof(*, leaf_data: bytes, leaf_index: int,
                           tree_size: int, proof_hashes, expected_root: bytes) -> None:
    """Verify an RFC 6962 audit path. Raises RekorVerificationError on
    any failure; returns None on success.

    Algorithm (RFC 6962 s2.1.1 / RFC 9162): walk leaf-to-root; at each
    level, if the current node is a right child (index odd) OR the
    remaining subtree has no right sibling to consume, combine with the
    proof hash on the left; otherwise on the right. A left-position
    node at the exact end of an odd level is promoted without a
    sibling — the proof supplies no hash for that step.
    """
    if not isinstance(leaf_data, bytes):
        raise RekorVerificationError("leaf_data must be bytes")
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool) or leaf_index < 0:
        raise RekorVerificationError(f"leaf_index must be a non-negative int, got {leaf_index!r}")
    if not isinstance(tree_size, int) or isinstance(tree_size, bool) or tree_size <= 0:
        raise RekorVerificationError(f"tree_size must be a positive int, got {tree_size!r}")
    if leaf_index >= tree_size:
        raise RekorVerificationError(
            f"leaf_index {leaf_index} out of range for tree_size {tree_size}")
    for i, h in enumerate(proof_hashes):
        if not isinstance(h, bytes) or len(h) != 32:
            raise RekorVerificationError(f"proof hash {i} must be 32 bytes")
    if not isinstance(expected_root, bytes) or len(expected_root) != 32:
        raise RekorVerificationError("expected_root must be 32 bytes")

    node = _leaf_hash(leaf_data)
    index, size = leaf_index, tree_size
    proof = list(proof_hashes)
    pos = 0
    while size > 1:
        if index % 2 == 1:
            # right child: sibling on the left, always exists
            if pos >= len(proof):
                raise RekorVerificationError(
                    "proof truncated: ran out of hashes before reaching root")
            node = _node_hash(proof[pos], node)
            pos += 1
        elif index < size - 1:
            # left child with a right sibling
            if pos >= len(proof):
                raise RekorVerificationError(
                    "proof truncated: ran out of hashes before reaching root")
            node = _node_hash(node, proof[pos])
            pos += 1
        # else: lone node at odd level end — promoted, no proof hash consumed
        index //= 2
        size = (size + 1) // 2
    if pos != len(proof):
        raise RekorVerificationError(
            f"proof has {len(proof) - pos} unconsumed hash(es): "
            f"wrong proof for this index/size, or padded")
    if node != expected_root:
        raise RekorVerificationError(
            "recomputed root does not match expected root: leaf not "
            "included in this tree (or proof/index/size inconsistent)")


def verify_checkpoint_signature(body: bytes, signature: bytes,
                                log_public_key: Ed25519PublicKey) -> None:
    """Verify the log's Ed25519 signature over checkpoint body bytes
    against the PINNED log key. Raises RekorVerificationError on failure.

    The pinned key is the trust anchor that makes offline verification
    meaningful: an attacker who forges a checkpoint must forge this
    signature, and possession of the public key alone cannot do it.
    """
    if not isinstance(body, bytes) or not body:
        raise RekorVerificationError("checkpoint body must be non-empty bytes")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise RekorVerificationError("checkpoint signature must be 64 bytes")
    try:
        log_public_key.verify(signature, body)
    except InvalidSignature as e:
        raise RekorVerificationError(
            "checkpoint signature invalid against the pinned log key: "
            "checkpoint is forged, tampered, or from a different log") from e


# ---------------------------------------------------------------------------
# WO-4.2a: signed-note (checkpoint) parsing + ECDSA P-256 verification
#
# DISCOVERY (live rekor.sigstore.dev STH, 2026-08-07): the production
# log signs checkpoints with ECDSA P-256 (DER signatures), NOT Ed25519.
# verify_checkpoint_signature above (Ed25519) remains for synthetic/
# future logs; verify_checkpoint_ecdsa is the production path. The
# CALLER selects the function by the type of the PINNED key — never by
# sniffing signature bytes, because letting attacker-controlled input
# choose the verification algorithm is a downgrade-attack shape.
#
# Note format (sumdb signed note):
#   <origin>\n<tree_size>\n<base64 root>\n[extra lines...]\n
#   \n
#   \u2014 <name> <base64(4-byte keyhint || signature)>\n   [1..n lines]
# Body = everything through (and including) the newline BEFORE the
# blank separator line. Body bytes are returned VERBATIM — never
# re-serialized — so signature verification sees exactly what was
# signed (store-bytes-parse-on-read).
# ---------------------------------------------------------------------------
import base64 as _base64

from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.asymmetric import ec as _ec

_SIG_PREFIX = "\u2014 ".encode("utf-8")  # em dash + space


def parse_checkpoint_note(note: bytes):
    """Split a signed note into (body_bytes, signatures).

    signatures is a list of (name, key_hint_4bytes, sig_bytes).
    Raises RekorVerificationError on any malformation: missing blank-
    line separator, no signature lines, bad base64, or a signature
    blob shorter than the 4-byte key hint + 1.
    """
    if not isinstance(note, bytes) or not note:
        raise RekorVerificationError("note must be non-empty bytes")
    sep = note.find(b"\n\n")
    if sep == -1:
        raise RekorVerificationError(
            "malformed note: no blank-line separator between body and "
            "signature lines")
    body = note[:sep + 1]          # body includes its trailing \n
    sig_block = note[sep + 2:]     # after the blank line
    sigs = []
    for raw_line in sig_block.split(b"\n"):
        if not raw_line.strip():
            continue
        if not raw_line.startswith(_SIG_PREFIX):
            raise RekorVerificationError(
                f"malformed signature line (missing em-dash prefix): "
                f"{raw_line[:40]!r}")
        rest = raw_line[len(_SIG_PREFIX):]
        space = rest.rfind(b" ")
        if space == -1:
            raise RekorVerificationError(
                "malformed signature line: no name/signature separator")
        name = rest[:space].decode("utf-8", errors="strict")
        b64 = rest[space + 1:]
        try:
            blob = _base64.b64decode(b64, validate=True)
        except Exception as e:
            raise RekorVerificationError(
                f"signature line base64 invalid: {e}") from e
        if len(blob) < 5:
            raise RekorVerificationError(
                f"signature blob too short ({len(blob)} bytes): must be "
                f"4-byte key hint + signature")
        sigs.append((name, blob[:4], blob[4:]))
    if not sigs:
        raise RekorVerificationError("note contains no signature lines")
    return body, sigs


def verify_checkpoint_ecdsa(body: bytes, signature_der: bytes,
                            log_public_key) -> None:
    """Verify an ECDSA-P256/SHA-256 signature (DER) over checkpoint body
    bytes against the PINNED log key (production Rekor path). Raises
    RekorVerificationError on any failure."""
    if not isinstance(body, bytes) or not body:
        raise RekorVerificationError("checkpoint body must be non-empty bytes")
    if not isinstance(signature_der, bytes) or not signature_der:
        raise RekorVerificationError("signature must be non-empty bytes")
    if not isinstance(log_public_key, _ec.EllipticCurvePublicKey):
        raise RekorVerificationError(
            "log_public_key must be an EC public key for the ECDSA path "
            "(caller selects algorithm by pinned key type)")
    try:
        log_public_key.verify(signature_der, body,
                              _ec.ECDSA(_hashes.SHA256()))
    except Exception as e:
        raise RekorVerificationError(
            "ECDSA checkpoint signature invalid against the pinned log "
            "key: checkpoint is forged, tampered, or from a different "
            "log") from e
