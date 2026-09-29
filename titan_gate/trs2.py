"""TRS-2 agent-action receipt profile (FRD §2.1).

Structural properties enforced here, not by convention:

  1. No payload-bearing field exists in the schema — there is no field
     to fill (FRD FR-RCP-3 / AT-17). Only target_hash / attributes_hash
     carry references to content, and they must already be SHA-256 hex.
  2. outcome.recorded_by_source is a structural constant `true`:
     outcomes only ever enter the system from source telemetry
     (BRD KEY-03 / NG-04). Supplying any non-true value is a schema
     error, not a stored value. Explicit `true` is accepted
     (idempotent round-trip).
  3. The field set is CLOSED. Unknown fields at any level are rejected,
     so a payload field can never be smuggled in under another name.

This module defines the EVENT profile only. Chaining fields (seq,
prev_receipt_hash), signing, and JCS canonicalization are layered on
by the receipt writer / canonical.py — deliberately not here, so the
schema module has a single responsibility and no crypto imports.
"""

import re

__all__ = [
    "build_trs2_event",
    "TRS2SchemaError",
    "TRS2_TOP_LEVEL_FIELDS",
    "TRS2_ACTION_FIELDS",
    "TRS2_OUTCOME_FIELDS",
]


class TRS2SchemaError(ValueError):
    """A TRS-2 event violated the closed schema."""


TRS2_TOP_LEVEL_FIELDS = frozenset({
    "source_id", "source_event_id", "event_time", "ingest_time",
    "agent_ref", "principal_ref", "action", "outcome",
})

TRS2_ACTION_FIELDS = frozenset({
    "category", "operation", "target_hash", "attributes_hash",
})

TRS2_OUTCOME_FIELDS = frozenset({
    "value", "recorded_by_source",
})

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Fields that must be non-empty strings.
_STRING_FIELDS = (
    "source_id", "source_event_id", "event_time", "ingest_time",
    "agent_ref", "principal_ref",
)
_ACTION_STRING_FIELDS = ("category", "operation")
_ACTION_HASH_FIELDS = ("target_hash", "attributes_hash")


def _require_str(container: dict, field: str, where: str) -> None:
    v = container.get(field)
    if not isinstance(v, str) or not v:
        raise TRS2SchemaError(
            f"{where}.{field} must be a non-empty string, got {v!r}"
        )


def build_trs2_event(**kwargs) -> dict:
    """Validate kwargs against the TRS-2 profile and return the event dict.

    Raises TRS2SchemaError on: unknown fields (any level), missing
    fields, non-hex hashes, or a non-true recorded_by_source.
    """
    # --- Closed set, top level ---
    unknown = set(kwargs) - TRS2_TOP_LEVEL_FIELDS
    if unknown:
        raise TRS2SchemaError(
            f"unknown top-level field(s): {sorted(unknown)} — "
            f"TRS-2 has no payload-bearing field and the schema is closed"
        )
    missing = TRS2_TOP_LEVEL_FIELDS - set(kwargs)
    if missing:
        raise TRS2SchemaError(f"missing required field(s): {sorted(missing)}")

    for f in _STRING_FIELDS:
        _require_str(kwargs, f, "event")

    # --- action ---
    action = kwargs["action"]
    if not isinstance(action, dict):
        raise TRS2SchemaError(f"action must be a dict, got {type(action).__name__}")
    unknown = set(action) - TRS2_ACTION_FIELDS
    if unknown:
        raise TRS2SchemaError(
            f"unknown action field(s): {sorted(unknown)} — "
            f"action carries hashes only, never content"
        )
    missing = TRS2_ACTION_FIELDS - set(action)
    if missing:
        raise TRS2SchemaError(f"missing action field(s): {sorted(missing)}")
    for f in _ACTION_STRING_FIELDS:
        _require_str(action, f, "action")
    for f in _ACTION_HASH_FIELDS:
        v = action.get(f)
        if not isinstance(v, str) or not _HEX64.fullmatch(v):
            raise TRS2SchemaError(
                f"action.{f} must be 64 lowercase hex chars (SHA-256), got {v!r}"
            )

    # --- outcome ---
    outcome = kwargs["outcome"]
    if not isinstance(outcome, dict):
        raise TRS2SchemaError(f"outcome must be a dict, got {type(outcome).__name__}")
    unknown = set(outcome) - TRS2_OUTCOME_FIELDS
    if unknown:
        raise TRS2SchemaError(f"unknown outcome field(s): {sorted(unknown)}")
    _require_str(outcome, "value", "outcome")

    # Structural constant: recorded_by_source is true by construction.
    # `is not True` (identity) deliberately rejects 1/0/"true"/None —
    # anything except the literal boolean True.
    if "recorded_by_source" in outcome and outcome["recorded_by_source"] is not True:
        raise TRS2SchemaError(
            "outcome.recorded_by_source is a structural constant `true`; "
            f"got {outcome['recorded_by_source']!r}. Outcomes enter only "
            "from source telemetry (BRD KEY-03/NG-04)."
        )

    return {
        "source_id": kwargs["source_id"],
        "source_event_id": kwargs["source_event_id"],
        "event_time": kwargs["event_time"],
        "ingest_time": kwargs["ingest_time"],
        "agent_ref": kwargs["agent_ref"],
        "principal_ref": kwargs["principal_ref"],
        "action": {
            "category": action["category"],
            "operation": action["operation"],
            "target_hash": action["target_hash"],
            "attributes_hash": action["attributes_hash"],
        },
        "outcome": {
            "value": outcome["value"],
            "recorded_by_source": True,
        },
    }
