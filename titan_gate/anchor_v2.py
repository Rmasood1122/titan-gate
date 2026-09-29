"""anchor_v2 — dual-leg anchor record: one root, two legs, disclosed degradation.

WO-5.2. Properties enforced (STRATEGY_DELTA D1, FR-RCP-2):
  * ONE top-level root; every present leg is checked against it. A record
    whose legs cover different roots is unrepresentable; a record CLAIMING
    a root its legs don't cover fails coherence, naming both roots in full.
  * A missing leg is DEGRADED with the leg named — never silently ANCHORED.
  * The PRESENT leg on a degraded record is still cryptographically
    verified; degraded-with-a-broken-leg is FAIL, not DEGRADED.
  * Zero legs refuses at build time (fail-closed — an anchor to nothing
    is not an anchor; TG-12 class).

Leg asymmetry (cryptographic fact, not a shortcut): the Rekor entry body
carries the covered artifact hash in plaintext, so its coherence check can
name claimed vs covered. An RFC 3161 token binds hash(root) — one-way — so
a TSA mismatch surfaces via the delegate's imprint binding, naming the
claimed root only.
"""
import base64
import binascii
import json
import re
from dataclasses import dataclass, field

from titan_gate.anchor_verify import (
    verify_anchor_record_offline,
    AnchorVerificationError,
)
from titan_gate.tsa_verify import verify_tsa_token_offline, TSAVerificationError

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
SCHEMA = "anchor_v2"


class AnchorV2Error(ValueError):
    """Any anchor_v2 build or verification failure. Fail-closed."""


@dataclass(frozen=True)
class AnchorV2Result:
    status: str                      # "ANCHORED" | "DEGRADED"
    legs_verified: frozenset
    missing_legs: frozenset
    tsa_time: object = None          # datetime from the TSA leg, if present


def _require_root(root_hash_hex):
    if not isinstance(root_hash_hex, str) or not _HEX64.fullmatch(root_hash_hex):
        raise AnchorV2Error("root_hash_hex must be 64 lowercase hex")
    return root_hash_hex


def build_anchor_v2_record(*, root_hash_hex, rekor_record, tsa_token):
    """Build a JSON-serializable anchor_v2 record. Refuses zero legs."""
    root = _require_root(root_hash_hex)
    if rekor_record is None and tsa_token is None:
        raise AnchorV2Error(
            "refusing to build an anchor record with zero legs — "
            "an anchor to nothing is not an anchor (fail-closed)")
    if tsa_token is not None and not isinstance(tsa_token, (bytes, bytearray)):
        raise AnchorV2Error(
            f"tsa_token must be bytes, got {type(tsa_token).__name__}")
    if rekor_record is not None and not isinstance(rekor_record, dict):
        raise AnchorV2Error(
            f"rekor_record must be dict, got {type(rekor_record).__name__}")
    return {
        "schema": SCHEMA,
        "root_hash_hex": root,
        "legs": {
            "rekor": rekor_record,
            "tsa": (base64.b64encode(bytes(tsa_token)).decode("ascii")
                    if tsa_token is not None else None),
        },
    }


def _rekor_covered_root(rekor_record):
    """Extract the artifact hash the Rekor entry actually covers."""
    try:
        entry_body = base64.b64decode(rekor_record["entry_body_b64"],
                                      validate=True)
        entry = json.loads(entry_body)
        return entry["spec"]["data"]["hash"]["value"]
    except (KeyError, TypeError, binascii.Error,
            json.JSONDecodeError, ValueError) as e:
        raise AnchorV2Error(
            f"rekor leg: cannot extract covered hash: {e}") from e


def verify_anchor_v2_offline(rec, *, rekor_log_pubkey, tsa_ca_cert_pem):
    """Verify an anchor_v2 record fully offline. Returns AnchorV2Result;
    raises AnchorV2Error on any failure of any PRESENT leg."""
    if not isinstance(rec, dict) or rec.get("schema") != SCHEMA:
        raise AnchorV2Error(f"not an {SCHEMA} record")
    root = _require_root(rec.get("root_hash_hex"))
    legs = rec.get("legs")
    if not isinstance(legs, dict):
        raise AnchorV2Error("record has no legs object")
    rekor_record, tsa_b64 = legs.get("rekor"), legs.get("tsa")
    if rekor_record is None and tsa_b64 is None:
        raise AnchorV2Error(
            "record has zero legs — not an anchor (fail-closed)")

    verified, missing, tsa_time = set(), set(), None

    # --- Rekor leg: coherence FIRST (full-hex, names both), crypto second ---
    if rekor_record is not None:
        covered = _rekor_covered_root(rekor_record)
        if covered != root:
            raise AnchorV2Error(
                f"leg/root mismatch: record claims root {root} but the "
                f"rekor leg covers {covered} — the legs do not anchor "
                f"the claimed root")
        try:
            verify_anchor_record_offline(
                rekor_record, rekor_log_pubkey,
                expected_artifact_hash_hex=root)
        except AnchorVerificationError as e:
            raise AnchorV2Error(f"rekor leg failed: {e}") from e
        verified.add("rekor")
    else:
        missing.add("rekor")

    # --- TSA leg: imprint binding inside the delegate enforces the root ---
    if tsa_b64 is not None:
        try:
            token = base64.b64decode(tsa_b64, validate=True)
        except binascii.Error as e:
            raise AnchorV2Error(f"tsa leg not valid base64: {e}") from e
        try:
            tsa_time = verify_tsa_token_offline(
                token, root_hash_hex=root, ca_cert_pem=tsa_ca_cert_pem)
        except TSAVerificationError as e:
            raise AnchorV2Error(
                f"tsa leg failed for claimed root {root}: {e}") from e
        verified.add("tsa")
    else:
        missing.add("tsa")

    status = "ANCHORED" if not missing else "DEGRADED"
    return AnchorV2Result(status=status,
                          legs_verified=frozenset(verified),
                          missing_legs=frozenset(missing),
                          tsa_time=tsa_time)
