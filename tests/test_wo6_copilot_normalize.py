"""WO-6 AT: Copilot audit-record -> TRS-2 event normalizer.

Spec:
  - normalize_copilot_record(record, *, source_id, ingest_time) returns
    a dict that IS a valid TRS-2 event (built via build_trs2_event —
    single schema authority, no parallel validation).
  - Mapping: source_event_id <- Id (native ID, FR-ING-4 dedup key —
    NEVER surrogated: a record without Id is REJECTED, not guessed).
    event_time <- CreationTime; ingest_time caller-supplied (the
    normalizer is pure — no clock inside, per testability).
    principal_ref <- "user://" + UserId; agent_ref <- "copilot://" + AppHost.
  - EDGE HASHING (FR-RCP-3): Contexts/AccessedResources identifiers and
    all content-bearing values (URLs, filenames, ThreadId, message ids)
    are hashed into target_hash / attributes_hash. NO such value may
    survive in ANY field of the normalized event. TRS-2's closed schema
    means there is no field to smuggle them into — this AT proves the
    normalizer doesn't try.
  - Gatekeeping: RecordType != 261 or Operation != "CopilotInteraction"
    is REJECTED (this normalizer handles exactly one record class).
  - Determinism: same record -> byte-identical event (re-poll
    idempotency rides on this, with dedup as the second line).

Fixtures: verbatim AuditData bytes from the canonical schema doc
(tests/fixtures/copilot/, TG-5 wire-truth). [F]-at-fixture; live-tenant
behavior stays [A] until a real tenant runs this (Rule 3).
"""

import json
from pathlib import Path

import pytest

from titan_gate.trs2 import build_trs2_event  # noqa: F401 (schema authority)
from titan_gate.copilot_normalize import (       # does not exist yet -> RED
    normalize_copilot_record,
    CopilotNormalizeError,
)

FIXTURES = Path(__file__).parent / "fixtures" / "copilot"


def _load(n: int) -> dict:
    raw = (FIXTURES / f"example_{n}_auditdata.json").read_bytes()
    return json.loads(raw)


@pytest.fixture()
def word_record():
    return _load(1)   # AppHost=Word, has Contexts, empty AccessedResources


@pytest.fixture()
def bing_record():
    return _load(2)   # AppHost=Bing, has AccessedResources w/ SiteUrl


ARGS = dict(source_id="m365-audit", ingest_time="2026-08-06T12:00:00Z")


# ------------------------------------------------------------ happy path

def test_normalizes_word_fixture_to_valid_trs2_event(word_record):
    ev = normalize_copilot_record(word_record, **ARGS)
    # The output must survive the schema authority unchanged:
    rebuilt = build_trs2_event(
        source_id=ev["source_id"], source_event_id=ev["source_event_id"],
        event_time=ev["event_time"], ingest_time=ev["ingest_time"],
        agent_ref=ev["agent_ref"], principal_ref=ev["principal_ref"],
        action=dict(ev["action"]), outcome=dict(ev["outcome"]),
    )
    assert rebuilt == ev
    assert ev["source_event_id"] == "99b0a960-13a0-461f-8c5c-cb2316ea273d"
    assert ev["event_time"] == "2023-12-13T17:12:36"
    assert ev["ingest_time"] == ARGS["ingest_time"]
    assert ev["agent_ref"] == "copilot://Word"
    assert ev["principal_ref"].startswith("user://")
    assert ev["action"]["category"] == "copilot_interaction"
    assert ev["outcome"]["recorded_by_source"] is True


def test_normalizes_bing_fixture(bing_record):
    ev = normalize_copilot_record(bing_record, **ARGS)
    assert ev["source_event_id"] == "537312b6-dce7-4d9b-8b12-58283204b720"
    assert ev["agent_ref"] == "copilot://Bing"


def test_feeds_receipt_writer_end_to_end(word_record):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    from titan_gate.trs2_writer import (
        build_trs2_receipt_v2, verify_trs2_receipt_v2)
    priv = Ed25519PrivateKey.generate()
    ev = normalize_copilot_record(word_record, **ARGS)
    r = build_trs2_receipt_v2(receipt_type="action", event=ev,
                              tenant_id="tenant-1", seq=0,
                              prev_receipt_hash="GENESIS",
                              sign_fn=lambda d: priv.sign(d), key_id="k1")
    verify_trs2_receipt_v2(r, priv.public_key())


# --------------------------------------------------- FR-RCP-3: no leakage

# Content-bearing strings present verbatim in the fixtures. If ANY of
# these survives anywhere in the normalized event, edge hashing failed.
WORD_LEAKS = [
    "AboutElephants.docx", "sharepoint.com", "sourcedoc",
    "19:lgojcxwbvhJnfU3IhUJW5M-nSX2U7tjccgSrtYAoG341@thread.v2",
    "1715187560311",                      # message id
    "10.11.0.229",                        # ClientIP fragment
]
BING_LEAKS = [
    "Document1.docx", "microsoft.sharepoint.com", "OfficeSerbia",
    "AAAAAEYE2GAACp1FlnN_CHXStUkHAGWJYgtgcv1eOxe2v4H4jOsAAAQsLLeAAGWJYgtgcv1EoXe2v4H4josAABwvq8gAAA2",
    "f41ab342-8706-4188-bd11-ebb85995028c",  # SensitivityLabelId
    "19:Xn3uQZYgZ7f2ue0vp5w9MglEVjFyp5pza1efaC6g2U41@thread.v2",
]


@pytest.mark.parametrize("n,leaks", [(1, WORD_LEAKS), (2, BING_LEAKS)])
def test_no_content_bearing_value_survives(n, leaks):
    ev = normalize_copilot_record(_load(n), **ARGS)
    serialized = json.dumps(ev)
    for leak in leaks:
        assert leak not in serialized, f"content leaked: {leak!r}"


def test_hashes_are_real_hashes(word_record):
    ev = normalize_copilot_record(word_record, **ARGS)
    for f in ("target_hash", "attributes_hash"):
        v = ev["action"][f]
        assert len(v) == 64 and set(v) <= set("0123456789abcdef")


# --------------------------------------------------------- gatekeeping

def test_missing_id_rejected_never_surrogated(word_record):
    del word_record["Id"]
    with pytest.raises(CopilotNormalizeError, match="Id"):
        normalize_copilot_record(word_record, **ARGS)


@pytest.mark.parametrize("field,bad", [
    ("RecordType", 15), ("Operation", "FileAccessed"),
])
def test_wrong_record_class_rejected(word_record, field, bad):
    word_record[field] = bad
    with pytest.raises(CopilotNormalizeError):
        normalize_copilot_record(word_record, **ARGS)


def test_missing_creation_time_rejected(word_record):
    del word_record["CreationTime"]
    with pytest.raises(CopilotNormalizeError):
        normalize_copilot_record(word_record, **ARGS)


# -------------------------------------------------------- determinism

def test_deterministic_same_record_same_event(word_record):
    a = normalize_copilot_record(_load(1), **ARGS)
    b = normalize_copilot_record(_load(1), **ARGS)
    assert a == b  # dict equality incl. both hashes


def test_different_records_different_hashes(word_record, bing_record):
    a = normalize_copilot_record(word_record, **ARGS)
    b = normalize_copilot_record(bing_record, **ARGS)
    assert a["action"]["target_hash"] != b["action"]["target_hash"]
