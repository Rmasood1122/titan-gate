"""Copilot audit-record -> TRS-2 event normalizer (WO-6).

PURE: no clock (ingest_time is caller-supplied), no network, no signing.
Schema authority is titan_gate.trs2.build_trs2_event — this module maps
and hashes, it never validates in parallel.

EDGE HASHING (FR-RCP-3): content-bearing values never survive into the
event. Preimage construction (normative for SPEC-2):

  target_hash    = SHA-256 over utf-8("\n".join(sorted(identifiers)))
                   where identifiers are "context.<K>:<V>" for each
                   string field of each Contexts entry, and
                   "resource.<K>:<V>" for each string field of each
                   AccessedResources entry.
  attributes_hash = SHA-256 over utf-8(json.dumps(
                   {"event_data": CopilotEventData minus
                    Contexts/AccessedResources,
                    "record": {ClientIP, ClientRegion, OrganizationId,
                    UserKey} as present},
                   sort_keys=True, separators=(",",":"),
                   ensure_ascii=False))

GATEKEEPING: exactly one record class — RecordType 261 +
Operation "CopilotInteraction". A record without a native Id is
REJECTED, never surrogated (FR-ING-4: this source HAS native IDs;
silently inventing one would corrupt the dedup key space).
"""

import hashlib
import json

from titan_gate.trs2 import build_trs2_event

__all__ = ["normalize_copilot_record", "CopilotNormalizeError"]

COPILOT_RECORD_TYPE = 261
COPILOT_OPERATION = "CopilotInteraction"


class CopilotNormalizeError(ValueError):
    """Record failed gatekeeping or required-field validation."""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_str(record: dict, field: str) -> str:
    v = record.get(field)
    if not isinstance(v, str) or not v:
        raise CopilotNormalizeError(
            f"{field} must be a non-empty string, got {v!r}"
            + (" — a record without a native Id is rejected, never"
               " surrogated" if field == "Id" else ""))
    return v


def normalize_copilot_record(record: dict, *, source_id: str,
                             ingest_time: str) -> dict:
    if not isinstance(record, dict):
        raise CopilotNormalizeError(
            f"record must be a dict, got {type(record).__name__}")
    if record.get("RecordType") != COPILOT_RECORD_TYPE:
        raise CopilotNormalizeError(
            f"RecordType must be {COPILOT_RECORD_TYPE}, "
            f"got {record.get('RecordType')!r} — this normalizer handles "
            f"exactly one record class")
    if record.get("Operation") != COPILOT_OPERATION:
        raise CopilotNormalizeError(
            f"Operation must be {COPILOT_OPERATION!r}, "
            f"got {record.get('Operation')!r}")

    event_id = _require_str(record, "Id")
    creation_time = _require_str(record, "CreationTime")
    user_id = _require_str(record, "UserId")

    ced = record.get("CopilotEventData")
    if not isinstance(ced, dict):
        raise CopilotNormalizeError(
            f"CopilotEventData must be a dict, got {type(ced).__name__}")
    app_host = ced.get("AppHost")
    if not isinstance(app_host, str) or not app_host:
        raise CopilotNormalizeError(
            f"CopilotEventData.AppHost must be a non-empty string, "
            f"got {app_host!r}")

    # --- target preimage: content identifiers, hashed at the edge ---
    identifiers = []
    for ctx in ced.get("Contexts") or []:
        if isinstance(ctx, dict):
            for k in sorted(ctx):
                if isinstance(ctx[k], str):
                    identifiers.append(f"context.{k}:{ctx[k]}")
    for rsc in ced.get("AccessedResources") or []:
        if isinstance(rsc, dict):
            for k in sorted(rsc):
                if isinstance(rsc[k], str):
                    identifiers.append(f"resource.{k}:{rsc[k]}")
    target_pre = "\n".join(sorted(identifiers)).encode("utf-8")

    # --- attributes preimage: remaining content-bearing metadata ---
    event_data = {k: v for k, v in ced.items()
                  if k not in ("Contexts", "AccessedResources")}
    record_extra = {k: record[k]
                    for k in ("ClientIP", "ClientRegion",
                              "OrganizationId", "UserKey")
                    if k in record}
    attrs_pre = json.dumps(
        {"event_data": event_data, "record": record_extra},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")

    return build_trs2_event(
        source_id=source_id,
        source_event_id=event_id,
        event_time=creation_time,
        ingest_time=ingest_time,
        agent_ref=f"copilot://{app_host}",
        principal_ref=f"user://{user_id}",
        action={
            "category": "copilot_interaction",
            "operation": COPILOT_OPERATION,
            "target_hash": _sha256_hex(target_pre),
            "attributes_hash": _sha256_hex(attrs_pre),
        },
        outcome={"value": "recorded"},
    )
