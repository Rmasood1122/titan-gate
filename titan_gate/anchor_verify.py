"""Offline verification of a Rekor anchor record (WO-4.3 part 1).

Composes proven pieces behind one function: the 6962 inclusion math
(rekor_inclusion), signed-note parsing + ECDSA checkpoint verification
(rekor_inclusion, WO-4.2a), and the anchor-record schema
(rekor_client, WO-4.2b). Zero network; the pinned log key is the
trust anchor.

Check order (deliberate — cheap coherence before crypto):
  1. Closed schema.
  2. Internal coherence: stored root_hash/tree_size must AGREE with
     the checkpoint's own body. A record whose halves disagree is the
     equivocation shape (TDD Narrative E) at record scale and FAILS
     before any signature math.
  3. Checkpoint signature against the PINNED key (ECDSA path — the
     production log's algorithm; caller pins the key, key type selects
     the algorithm per WO-4.2a).
  4. Inclusion: leaf = sha256(0x00 || entry_body_bytes) walked through
     the proof to the checkpoint root. The entry body VERBATIM as leaf
     content is the wire-taught contract this module encodes.
  5. Optional artifact binding: the entry body's covered hash must
     equal the caller's expected interval root — "an anchor exists"
     is worthless without "it anchors OUR root."
"""
import base64
import binascii
import hashlib
import json
import re

from cryptography.hazmat.primitives.asymmetric import ec as _ec

from titan_gate.rekor_client import ANCHOR_RECORD_FIELDS
from titan_gate.rekor_inclusion import (
    parse_checkpoint_note,
    verify_checkpoint_ecdsa,
    verify_inclusion_proof,
    RekorVerificationError,
)

__all__ = ["verify_anchor_record_offline", "AnchorVerificationError"]

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AnchorVerificationError(ValueError):
    """Anchor record failed offline verification."""


def verify_anchor_record_offline(record: dict, log_public_key,
                                 expected_artifact_hash_hex: str = None) -> None:
    """Verify one anchor record fully offline. Raises on any failure."""
    # --- 1. Schema ---
    if not isinstance(record, dict):
        raise AnchorVerificationError("record must be a dict")
    if set(record) != ANCHOR_RECORD_FIELDS:
        raise AnchorVerificationError(
            f"record fields {sorted(record)} != required "
            f"{sorted(ANCHOR_RECORD_FIELDS)}")
    if record["anchor_version"] != "rekor_v1":
        raise AnchorVerificationError(
            f"unknown anchor_version {record['anchor_version']!r}")
    if not _HEX64.fullmatch(record.get("root_hash") or ""):
        raise AnchorVerificationError("root_hash must be 64 lowercase hex")

    # --- 2. Internal coherence vs the checkpoint's own body ---
    cp_raw = record["checkpoint_raw"]
    cp_bytes = cp_raw.encode("utf-8") if isinstance(cp_raw, str) else cp_raw
    try:
        body, sigs = parse_checkpoint_note(cp_bytes)
    except RekorVerificationError as e:
        raise AnchorVerificationError(f"checkpoint unparseable: {e}") from e
    body_lines = body.decode("utf-8").split("\n")
    if len(body_lines) < 3:
        raise AnchorVerificationError("checkpoint body too short")
    try:
        cp_size = int(body_lines[1])
        cp_root_hex = base64.b64decode(body_lines[2], validate=True).hex()
    except (ValueError, binascii.Error) as e:
        raise AnchorVerificationError(
            f"checkpoint body malformed (size/root lines): {e}") from e
    if cp_size != record["tree_size"]:
        raise AnchorVerificationError(
            f"equivocation shape: record tree_size {record['tree_size']} "
            f"!= checkpoint size {cp_size}")
    if cp_root_hex != record["root_hash"]:
        raise AnchorVerificationError(
            "equivocation shape: record root_hash != checkpoint root")

    # --- 3. Checkpoint signature against the pinned key ---
    if not isinstance(log_public_key, _ec.EllipticCurvePublicKey):
        raise AnchorVerificationError(
            "pinned log key must be an EC public key (production Rekor "
            "signs checkpoints ECDSA P-256; key type selects algorithm)")
    _, _, sig = sigs[0]
    try:
        verify_checkpoint_ecdsa(body, sig, log_public_key)
    except RekorVerificationError as e:
        raise AnchorVerificationError(f"checkpoint signature: {e}") from e

    # --- 4. Inclusion: entry body verbatim is the leaf content ---
    try:
        entry_body = base64.b64decode(record["entry_body_b64"], validate=True)
    except binascii.Error as e:
        raise AnchorVerificationError(f"entry_body_b64 invalid: {e}") from e
    try:
        proof = [bytes.fromhex(h) for h in record["hashes"]]
    except ValueError as e:
        raise AnchorVerificationError(f"proof hashes not hex: {e}") from e
    try:
        verify_inclusion_proof(
            leaf_data=entry_body,
            leaf_index=record["log_index"],
            tree_size=record["tree_size"],
            proof_hashes=proof,
            expected_root=bytes.fromhex(record["root_hash"]))
    except RekorVerificationError as e:
        raise AnchorVerificationError(f"inclusion proof: {e}") from e

    # --- 5. Optional artifact binding ---
    if expected_artifact_hash_hex is not None:
        if not _HEX64.fullmatch(expected_artifact_hash_hex):
            raise AnchorVerificationError(
                "expected_artifact_hash_hex must be 64 lowercase hex")
        try:
            entry = json.loads(entry_body)
            covered = entry["spec"]["data"]["hash"]["value"]
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            raise AnchorVerificationError(
                f"entry body missing covered hash: {e}") from e
        if covered != expected_artifact_hash_hex:
            raise AnchorVerificationError(
                f"anchor covers {covered[:16]}..., not the expected "
                f"artifact {expected_artifact_hash_hex[:16]}... — an "
                f"anchor exists, but it does not anchor THIS root")
