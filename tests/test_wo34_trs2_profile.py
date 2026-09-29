"""WO-3.4 AT — TRS-2 agent-action receipt profile (FRD §2.1, AT-17 shape).

Pins three structural properties before implementation exists:
  1. NO payload-bearing field exists anywhere in the schema — there is
     no field to fill (FRD FR-RCP-3 / AT-17).
  2. outcome.recorded_by_source is a structural constant `true`. It is
     not caller-settable to anything else; supplying false (or any
     non-true value) is a schema error, not a stored value (FRD §2.1,
     KEY-03/NG-04 lineage).
  3. The field set is CLOSED: unknown fields at top level or inside
     action/outcome are rejected, so a payload field can never be
     smuggled in under another name.

Expected state on first run: RED (titan_gate.trs2 does not exist).
"""
import pytest

from titan_gate.trs2 import (
    build_trs2_event,
    TRS2SchemaError,
    TRS2_TOP_LEVEL_FIELDS,
    TRS2_ACTION_FIELDS,
    TRS2_OUTCOME_FIELDS,
)

HEX64_A = "a" * 64
HEX64_B = "b" * 64


def valid_kwargs():
    return dict(
        source_id="copilot-export-test",
        source_event_id="evt-0001",
        event_time="2026-08-06T12:00:00Z",
        ingest_time="2026-08-06T12:00:41Z",
        agent_ref="agent-42",
        principal_ref="user:test-principal",
        action=dict(
            category="data_access",
            operation="read",
            target_hash=HEX64_A,
            attributes_hash=HEX64_B,
        ),
        outcome=dict(value="success"),
    )


# --- 1. Happy path + structural constant injection ---

def test_valid_event_builds_and_injects_structural_constant():
    ev = build_trs2_event(**valid_kwargs())
    assert ev["outcome"]["recorded_by_source"] is True
    assert ev["outcome"]["value"] == "success"


def test_recorded_by_source_explicit_true_is_accepted():
    kw = valid_kwargs()
    kw["outcome"]["recorded_by_source"] = True
    ev = build_trs2_event(**kw)
    assert ev["outcome"]["recorded_by_source"] is True


@pytest.mark.parametrize("bad", [False, None, "true", 1, 0])
def test_recorded_by_source_non_true_is_schema_error(bad):
    kw = valid_kwargs()
    kw["outcome"]["recorded_by_source"] = bad
    with pytest.raises(TRS2SchemaError):
        build_trs2_event(**kw)


# --- 2. No payload-bearing field, anywhere, under any name ---

FORBIDDEN_NAMES = [
    "payload", "content", "body", "raw", "raw_payload", "data",
    "prompt", "response", "message", "text", "target", "attributes",
]

@pytest.mark.parametrize("name", FORBIDDEN_NAMES)
def test_payload_bearing_top_level_field_rejected(name):
    kw = valid_kwargs()
    kw[name] = "anything"
    with pytest.raises(TRS2SchemaError):
        build_trs2_event(**kw)


@pytest.mark.parametrize("name", FORBIDDEN_NAMES)
def test_payload_bearing_action_field_rejected(name):
    kw = valid_kwargs()
    kw["action"][name] = "anything"
    with pytest.raises(TRS2SchemaError):
        build_trs2_event(**kw)


def test_schema_field_sets_are_exactly_frd_2_1():
    assert TRS2_TOP_LEVEL_FIELDS == frozenset({
        "source_id", "source_event_id", "event_time", "ingest_time",
        "agent_ref", "principal_ref", "action", "outcome",
    })
    assert TRS2_ACTION_FIELDS == frozenset({
        "category", "operation", "target_hash", "attributes_hash",
    })
    assert TRS2_OUTCOME_FIELDS == frozenset({
        "value", "recorded_by_source",
    })


# --- 3. Closed set: unknown fields rejected; hashes are hashes ---

def test_unknown_top_level_field_rejected():
    kw = valid_kwargs()
    kw["vendor_note"] = "x"
    with pytest.raises(TRS2SchemaError):
        build_trs2_event(**kw)


def test_missing_required_field_rejected():
    kw = valid_kwargs()
    del kw["agent_ref"]
    with pytest.raises(TRS2SchemaError):
        build_trs2_event(**kw)


@pytest.mark.parametrize("field", ["target_hash", "attributes_hash"])
def test_action_hashes_must_be_64_hex(field):
    kw = valid_kwargs()
    kw["action"][field] = "not-a-hash"
    with pytest.raises(TRS2SchemaError):
        build_trs2_event(**kw)


# --- 4. Hash validation is fullmatch: no trailing garbage survives ---

@pytest.mark.parametrize("bad", [
    HEX64_A + "\n",      # trailing newline ($ in re.match tolerates this)
    HEX64_A + "x",       # trailing char
    "A" * 64,            # uppercase hex — canonical form is lowercase only
])
def test_hash_rejects_non_canonical_forms(bad):
    kw = valid_kwargs()
    kw["action"]["target_hash"] = bad
    with pytest.raises(TRS2SchemaError):
        build_trs2_event(**kw)
