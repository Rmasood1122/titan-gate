"""TRS-2 receipt writer: build, digest, and verify agent-action receipts.

Trust-domain seam (Rule 1, FRD FR-KEY-1): this module holds NO key
material and cannot sign. Signing is requested via an injected sign_fn
callable — the V3->C1 relationship at module scale. sign_fn receives
the 32 raw SHA-256 digest bytes and returns the Ed25519 signature
bytes; today's callers inject a local signer, WO-7 swaps in an HTTP
call to the customer-side container with no change here.

Verification requires only a PUBLIC key. This module may import the
public-key type; it must never import a signing-capable type, key
env-var name, or anything from the api/ layer (executable lint:
tests/test_wo34_trs2_writer.py::test_writer_module_imports_no_key_material).

Digest rule (SPEC-2 §4 / FRD §2.2): body = receipt minus sig and the
stored receipt_hash; digest = SHA-256(JCS(body)). The body INCLUDES
prev_receipt_hash — the chain link is under the signature.
"""
import hashlib
import re
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from titan_gate.canonical import canonical_bytes_jcs, JCSError
from titan_gate.trs2 import build_trs2_event, TRS2SchemaError

__all__ = [
    "build_trs2_receipt",
    "verify_trs2_receipt",
    "TRS2ReceiptError",
    "TRS2_SCHEMA_VERSION",
]

TRS2_SCHEMA_VERSION = "receipt_trs2_v1"
_SIG_ALG = "ed25519-v1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

RECEIPT_FIELDS = frozenset({
    "schema_version", "receipt_id", "tenant_id", "seq",
    "prev_receipt_hash", "event", "receipt_hash", "sig",
})
SIG_FIELDS = frozenset({"key_id", "alg", "value"})

class TRS2ReceiptError(ValueError):
    """Receipt failed structural validation or cryptographic verification."""

def _body_digest_hex(body: dict) -> str:
    try:
        return hashlib.sha256(canonical_bytes_jcs(body)).hexdigest()
    except JCSError as e:
        raise TRS2ReceiptError(f"body not canonicalizable: {e}") from e

def _check_prev(prev: str) -> None:
    if prev != "GENESIS" and not _HEX64.fullmatch(prev or ""):
        raise TRS2ReceiptError(
            f"prev_receipt_hash must be 'GENESIS' or 64 lowercase hex, got {prev!r}"
        )

def build_trs2_receipt(*, event: dict, tenant_id: str, seq: int,
                       prev_receipt_hash: str, sign_fn, key_id: str) -> dict:
    """Assemble, digest, and sign one TRS-2 receipt.

    event MUST already be valid per titan_gate.trs2 (re-validated here
    so an unvalidated dict cannot slip through a second entry point).
    """
    # Re-validate the event: defense in depth, and rejects a dict that
    # was mutated after build_trs2_event returned it.
    event = build_trs2_event(
        source_id=event.get("source_id"),
        source_event_id=event.get("source_event_id"),
        event_time=event.get("event_time"),
        ingest_time=event.get("ingest_time"),
        agent_ref=event.get("agent_ref"),
        principal_ref=event.get("principal_ref"),
        action=dict(event.get("action") or {}),
        outcome=dict(event.get("outcome") or {}),
    )
    if not isinstance(tenant_id, str) or not tenant_id:
        raise TRS2ReceiptError(f"tenant_id must be a non-empty string, got {tenant_id!r}")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise TRS2ReceiptError(f"seq must be a non-negative int, got {seq!r}")
    if seq == 0 and prev_receipt_hash != "GENESIS":
        raise TRS2ReceiptError("seq 0 requires prev_receipt_hash 'GENESIS'")
    if seq > 0 and prev_receipt_hash == "GENESIS":
        raise TRS2ReceiptError("non-genesis receipt cannot claim GENESIS prev")
    _check_prev(prev_receipt_hash)
    if not isinstance(key_id, str) or not key_id:
        raise TRS2ReceiptError(f"key_id must be a non-empty string, got {key_id!r}")

    body = {
        "schema_version": TRS2_SCHEMA_VERSION,
        # NOTE: FRD §2.2 specifies UUIDv7; stdlib uuid7 lands in 3.14.
        # uuid4 used deliberately for now — seq carries ordering, the id
        # only needs uniqueness. Revisit at 3.14 or if an external
        # consumer needs time-sortable ids. (Conscious deviation, not drift.)
        "receipt_id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "seq": seq,
        "prev_receipt_hash": prev_receipt_hash,
        "event": event,
    }
    digest_hex = _body_digest_hex(body)
    sig_bytes = sign_fn(bytes.fromhex(digest_hex))
    if not isinstance(sig_bytes, bytes) or len(sig_bytes) != 64:
        raise TRS2ReceiptError(
            f"sign_fn must return 64 signature bytes, got {type(sig_bytes).__name__}"
            f"/{len(sig_bytes) if isinstance(sig_bytes, bytes) else 'n-a'}"
        )
    receipt = dict(body)
    receipt["receipt_hash"] = digest_hex
    receipt["sig"] = {"key_id": key_id, "alg": _SIG_ALG, "value": sig_bytes.hex()}
    return receipt

def verify_trs2_receipt(receipt: dict, public_key: Ed25519PublicKey) -> None:
    """Verify one receipt structurally and cryptographically. Raises on any failure.

    Checks: closed field sets, schema_version, prev format, seq/GENESIS
    consistency, event validity, digest recomputation over JCS(body),
    and the Ed25519 signature over the raw digest bytes.
    """
    if not isinstance(receipt, dict):
        raise TRS2ReceiptError("receipt must be a dict")
    unknown = set(receipt) - RECEIPT_FIELDS
    if unknown:
        raise TRS2ReceiptError(f"unknown receipt field(s): {sorted(unknown)}")
    missing = RECEIPT_FIELDS - set(receipt)
    if missing:
        raise TRS2ReceiptError(f"missing receipt field(s): {sorted(missing)}")
    if receipt["schema_version"] != TRS2_SCHEMA_VERSION:
        raise TRS2ReceiptError(
            f"schema_version must be {TRS2_SCHEMA_VERSION!r}, "
            f"got {receipt['schema_version']!r}"
        )
    seq = receipt["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise TRS2ReceiptError(f"seq must be a non-negative int, got {seq!r}")
    prev = receipt["prev_receipt_hash"]
    _check_prev(prev)
    if (seq == 0) != (prev == "GENESIS"):
        raise TRS2ReceiptError("seq/GENESIS mismatch")

    sig = receipt["sig"]
    if not isinstance(sig, dict) or set(sig) != SIG_FIELDS:
        raise TRS2ReceiptError("sig must contain exactly key_id, alg, value")
    if sig["alg"] != _SIG_ALG:
        raise TRS2ReceiptError(f"sig.alg must be {_SIG_ALG!r}, got {sig['alg']!r}")

    ev = receipt["event"]
    if not isinstance(ev, dict):
        raise TRS2ReceiptError("event must be a dict")
    try:
        _rebuilt = build_trs2_event(
            source_id=ev.get("source_id"),
            source_event_id=ev.get("source_event_id"),
            event_time=ev.get("event_time"),
            ingest_time=ev.get("ingest_time"),
            agent_ref=ev.get("agent_ref"),
            principal_ref=ev.get("principal_ref"),
            action=dict(ev.get("action") or {}),
            outcome=dict(ev.get("outcome") or {}),
        )
    except TRS2SchemaError as e:
        raise TRS2ReceiptError(f"event invalid: {e}") from e
    else:
        # P11 fix: the rebuild above cherry-picks known fields, so an
        # unknown TOP-LEVEL event field would escape it (nested extras
        # are caught inside build_trs2_event). Rebuilt must equal
        # stored exactly — closes smuggling at every level.
        if _rebuilt != ev:
            extra = sorted(set(ev) - set(_rebuilt))
            raise TRS2ReceiptError(
                f"event contains field(s) outside the closed schema: "
                f"{extra or 'value divergence'} — no field to fill")

    body = {k: v for k, v in receipt.items() if k not in ("sig", "receipt_hash")}
    digest_hex = _body_digest_hex(body)
    if digest_hex != receipt["receipt_hash"]:
        raise TRS2ReceiptError(
            "receipt_hash mismatch: body was altered after signing"
        )
    if not isinstance(sig["value"], str) or not re.fullmatch(r"[0-9a-f]{128}", sig["value"]):
        raise TRS2ReceiptError("sig.value must be 128 lowercase hex chars")
    try:
        public_key.verify(bytes.fromhex(sig["value"]), bytes.fromhex(digest_hex))
    except InvalidSignature as e:
        raise TRS2ReceiptError(
            "signature invalid for this public key over the recomputed digest"
        ) from e

# =====================================================================
# WO-6: receipt_trs2_v2 — adds required receipt_type {action,gap,marker}
# (SPEC-2 amendment). Strictly additive: v1 above is golden-pinned and
# untouched. Gaps are OUR statement about source silence (FR-ING-6);
# they carry no event and no outcome — a gap with an outcome would
# forge recorded_by_source. receipt_type lives INSIDE the signed body
# so relabeling a signed receipt fails digest recomputation.
# =====================================================================

from cryptography.exceptions import InvalidSignature

TRS2_SCHEMA_VERSION_V2 = "receipt_trs2_v2"
RECEIPT_TYPES = frozenset({"action", "gap", "marker"})  # admin RESERVED

_RECEIPT_BASE_FIELDS_V2 = frozenset({
    "schema_version", "receipt_id", "tenant_id", "seq",
    "prev_receipt_hash", "receipt_type", "receipt_hash", "sig",
})
_GAP_OPEN_FIELDS = frozenset({"source_id", "interval_start"})
_GAP_CLOSE_FIELDS = frozenset({"source_id", "interval_start", "interval_end"})

def _validate_gap_block(gap: dict, receipt_type: str) -> dict:
    """Closed-set validation of a gap/marker block. Returns a clean copy.

    Open gap = exactly {source_id, interval_start}; a claimed
    interval_end on an OPEN gap is rejected — that shape is a marker.
    Marker = exactly the close shape. Unknown fields rejected at any
    membership (the P11 no-smuggling property, by construction).
    """
    if not isinstance(gap, dict):
        raise TRS2ReceiptError(f"gap must be a dict, got {type(gap).__name__}")
    expected = _GAP_OPEN_FIELDS if receipt_type == "gap" else _GAP_CLOSE_FIELDS
    if set(gap) != expected:
        raise TRS2ReceiptError(
            f"{receipt_type} gap block must contain exactly "
            f"{sorted(expected)}, got {sorted(gap)}")
    for f in sorted(expected):
        v = gap[f]
        if not isinstance(v, str) or not v:
            raise TRS2ReceiptError(
                f"gap.{f} must be a non-empty string, got {v!r}")
    return {f: gap[f] for f in sorted(expected)}

def build_trs2_receipt_v2(*, receipt_type, tenant_id: str, seq: int,
                          prev_receipt_hash: str, sign_fn, key_id: str,
                          event: dict | None = None,
                          gap: dict | None = None) -> dict:
    """Assemble, digest, and sign one v2 receipt. Additive to v1."""
    if receipt_type not in RECEIPT_TYPES:
        raise TRS2ReceiptError(
            f"receipt_type must be one of {sorted(RECEIPT_TYPES)}, "
            f"got {receipt_type!r}")

    if receipt_type == "action":
        if gap is not None:
            raise TRS2ReceiptError("action receipt must not carry a gap block")
        if event is None:
            raise TRS2ReceiptError("action receipt requires an event")
        # Re-validate (defense in depth, same as v1 builder).
        content_key = "event"
        content = build_trs2_event(
            source_id=event.get("source_id"),
            source_event_id=event.get("source_event_id"),
            event_time=event.get("event_time"),
            ingest_time=event.get("ingest_time"),
            agent_ref=event.get("agent_ref"),
            principal_ref=event.get("principal_ref"),
            action=dict(event.get("action") or {}),
            outcome=dict(event.get("outcome") or {}),
        )
    else:  # gap | marker
        if event is not None:
            raise TRS2ReceiptError(
                f"{receipt_type} receipt must not carry an event")
        if gap is None:
            raise TRS2ReceiptError(
                f"{receipt_type} receipt requires a gap block")
        content_key = "gap"
        content = _validate_gap_block(gap, receipt_type)

    if not isinstance(tenant_id, str) or not tenant_id:
        raise TRS2ReceiptError(
            f"tenant_id must be a non-empty string, got {tenant_id!r}")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise TRS2ReceiptError(f"seq must be a non-negative int, got {seq!r}")
    if seq == 0 and prev_receipt_hash != "GENESIS":
        raise TRS2ReceiptError("seq 0 requires prev_receipt_hash 'GENESIS'")
    if seq > 0 and prev_receipt_hash == "GENESIS":
        raise TRS2ReceiptError("non-genesis receipt cannot claim GENESIS prev")
    _check_prev(prev_receipt_hash)
    if not isinstance(key_id, str) or not key_id:
        raise TRS2ReceiptError(
            f"key_id must be a non-empty string, got {key_id!r}")

    body = {
        "schema_version": TRS2_SCHEMA_VERSION_V2,
        "receipt_id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "seq": seq,
        "prev_receipt_hash": prev_receipt_hash,
        "receipt_type": receipt_type,
        content_key: content,
    }
    digest_hex = _body_digest_hex(body)
    sig_bytes = sign_fn(bytes.fromhex(digest_hex))
    if not isinstance(sig_bytes, bytes) or len(sig_bytes) != 64:
        raise TRS2ReceiptError(
            f"sign_fn must return 64 signature bytes, got "
            f"{type(sig_bytes).__name__}"
            f"/{len(sig_bytes) if isinstance(sig_bytes, bytes) else 'n-a'}")
    receipt = dict(body)
    receipt["receipt_hash"] = digest_hex
    receipt["sig"] = {"key_id": key_id, "alg": _SIG_ALG,
                      "value": sig_bytes.hex()}
    return receipt

def verify_trs2_receipt_v2(receipt: dict,
                           public_key: Ed25519PublicKey) -> None:
    """Verify one v2 receipt structurally and cryptographically.

    Field set is TYPE-DISPATCHED: receipt_type is read first (and
    re-checked against the signed digest at the end, so a relabeled
    receipt cannot steer verification into a lenient path and pass).
    """
    if not isinstance(receipt, dict):
        raise TRS2ReceiptError("receipt must be a dict")
    rtype = receipt.get("receipt_type")

    if not isinstance(rtype, str):

        raise TRS2ReceiptError(

            f"receipt_type must be a string, got "

            f"{type(rtype).__name__}")
    if rtype not in RECEIPT_TYPES:
        raise TRS2ReceiptError(
            f"receipt_type must be one of {sorted(RECEIPT_TYPES)}, "
            f"got {rtype!r}")
    content_key = "event" if rtype == "action" else "gap"
    expected_fields = _RECEIPT_BASE_FIELDS_V2 | {content_key}
    unknown = set(receipt) - expected_fields
    if unknown:
        raise TRS2ReceiptError(f"unknown receipt field(s): {sorted(unknown)}")
    missing = expected_fields - set(receipt)
    if missing:
        raise TRS2ReceiptError(f"missing receipt field(s): {sorted(missing)}")
    if receipt["schema_version"] != TRS2_SCHEMA_VERSION_V2:
        raise TRS2ReceiptError(
            f"schema_version must be {TRS2_SCHEMA_VERSION_V2!r}, "
            f"got {receipt['schema_version']!r}")
    seq = receipt["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise TRS2ReceiptError(f"seq must be a non-negative int, got {seq!r}")
    prev = receipt["prev_receipt_hash"]
    _check_prev(prev)
    if (seq == 0) != (prev == "GENESIS"):
        raise TRS2ReceiptError("seq/GENESIS mismatch")

    sig = receipt["sig"]
    if not isinstance(sig, dict) or set(sig) != SIG_FIELDS:
        raise TRS2ReceiptError("sig must contain exactly key_id, alg, value")
    if sig["alg"] != _SIG_ALG:
        raise TRS2ReceiptError(
            f"sig.alg must be {_SIG_ALG!r}, got {sig['alg']!r}")

    # --- content validation (P11 rebuild-equality per type) ---
    if rtype == "action":
        ev = receipt["event"]
        if not isinstance(ev, dict):
            raise TRS2ReceiptError("event must be a dict")
        try:
            rebuilt = build_trs2_event(
                source_id=ev.get("source_id"),
                source_event_id=ev.get("source_event_id"),
                event_time=ev.get("event_time"),
                ingest_time=ev.get("ingest_time"),
                agent_ref=ev.get("agent_ref"),
                principal_ref=ev.get("principal_ref"),
                action=dict(ev.get("action") or {}),
                outcome=dict(ev.get("outcome") or {}),
            )
        except TRS2SchemaError as e:
            raise TRS2ReceiptError(f"event invalid: {e}") from e
        if rebuilt != ev:
            raise TRS2ReceiptError(
                "event does not equal its canonical rebuild "
                "(unknown top-level field?)")
    else:
        # Closed-set validation IS rebuild-equality here: every field
        # is enumerated and checked, so no residue can differ.
        _validate_gap_block(receipt["gap"], rtype)

    # --- digest recomputation over the signed body ---
    body = {k: v for k, v in receipt.items()
            if k not in ("receipt_hash", "sig")}
    digest_hex = _body_digest_hex(body)
    if digest_hex != receipt["receipt_hash"]:
        raise TRS2ReceiptError(
            "receipt_hash does not match recomputed body digest")

    try:
        sig_bytes = bytes.fromhex(sig["value"])
    except (ValueError, TypeError) as e:
        raise TRS2ReceiptError(f"sig.value is not valid hex: {e}") from e
    try:
        public_key.verify(sig_bytes, bytes.fromhex(digest_hex))
    except InvalidSignature as e:
        raise TRS2ReceiptError("Ed25519 signature verification failed") from e

__all__ += [
    "build_trs2_receipt_v2",
    "verify_trs2_receipt_v2",
    "TRS2_SCHEMA_VERSION_V2",
    "RECEIPT_TYPES",
]
