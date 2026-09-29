"""WO-6 AT: CopilotPoller — fetch seam -> normalize -> dedup -> chain.

Spec: CopilotPoller(fetch_fn, assembler, window_overlap_s=60).
poll(now) computes the window, calls fetch_fn(start, end), filters
non-CopilotInteraction records (counted), normalizes 261s (failures
rejected+counted, poll continues), dedups against the CHAIN (already-
receipted source_event_ids skipped), hands survivors to
assembler.record_poll. Returns PollReport. fetch_fn raising ->
empty-poll semantics + fetch_error disclosed; sustained failure
becomes a gap via the assembler's threshold. Wire client is [A]:
this AT proves everything below the seam.
"""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from titan_gate.ingest_assembler import ChainAssembler
from titan_gate.copilot_poller import (   # does not exist yet -> RED
    CopilotPoller,
    PollReport,
)

FIXTURES = Path(__file__).parent / "fixtures" / "copilot"


def _record(n: int) -> dict:
    return json.loads((FIXTURES / f"example_{n}_auditdata.json").read_bytes())


@pytest.fixture()
def keys():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


@pytest.fixture()
def asm(tmp_path, keys):
    priv, _ = keys
    return ChainAssembler(
        receipts_root=tmp_path / "receipts", tenant_id="tenant-1",
        source_id="m365-audit", key_id="k1",
        sign_fn=lambda d: priv.sign(d), silence_threshold_s=600)


def _receipts(root):
    rs = [json.loads(p.read_text(encoding="utf-8"))
          for p in sorted(Path(root).rglob("*.json"))]
    return sorted(rs, key=lambda r: r["seq"])


T0 = "2026-08-06T10:00:00+00:00"
T1 = "2026-08-06T10:05:00+00:00"
T2 = "2026-08-06T10:30:00+00:00"


def test_poll_receipts_fixture_records(asm):
    p = CopilotPoller(fetch_fn=lambda s, e: [_record(1), _record(2)],
                      assembler=asm)
    rep = p.poll(T0)
    assert isinstance(rep, PollReport)
    assert rep.fetched == 2 and rep.receipted == 2
    assert rep.rejected == 0 and rep.deduped == 0
    assert rep.fetch_error is None
    rs = _receipts(asm.receipts_root)
    assert [r["receipt_type"] for r in rs] == ["action", "action"]


def test_repoll_overlap_dedups_via_chain(asm):
    p = CopilotPoller(fetch_fn=lambda s, e: [_record(1), _record(2)],
                      assembler=asm)
    p.poll(T0)
    rep = p.poll(T1)                      # same records again (overlap)
    assert rep.deduped == 2 and rep.receipted == 0
    assert len(_receipts(asm.receipts_root)) == 2   # chain unchanged


def test_mixed_feed_skips_other_record_types(asm):
    other = dict(_record(1), RecordType=15, Id="not-a-copilot-record")
    p = CopilotPoller(fetch_fn=lambda s, e: [other, _record(2)],
                      assembler=asm)
    rep = p.poll(T0)
    assert rep.skipped_other_type == 1 and rep.receipted == 1
    (r,) = _receipts(asm.receipts_root)
    assert r["event"]["source_event_id"] == _record(2)["Id"]


def test_malformed_261_rejected_poll_continues(asm):
    bad = _record(1); del bad["Id"]       # 261 but unusable
    p = CopilotPoller(fetch_fn=lambda s, e: [bad, _record(2)],
                      assembler=asm)
    rep = p.poll(T0)
    assert rep.rejected == 1 and rep.receipted == 1


def test_fetch_failure_is_disclosed_silence(asm):
    calls = {"n": 0}
    def flaky(s, e):
        calls["n"] += 1
        if calls["n"] == 1:
            return [_record(1)]
        raise ConnectionError("api down")
    p = CopilotPoller(fetch_fn=flaky, assembler=asm)
    p.poll(T0)                            # activity
    rep = p.poll(T1)                      # fetch fails, 5min: no gap yet
    assert rep.fetch_error is not None and rep.receipted == 0
    p.poll(T2)                            # fails again, 30min > threshold
    rs = _receipts(asm.receipts_root)
    assert [r["receipt_type"] for r in rs] == ["action", "gap"]


def test_assembled_chain_passes_v2_walk(asm, keys):
    _, pub = keys
    p = CopilotPoller(fetch_fn=lambda s, e: [_record(1), _record(2)],
                      assembler=asm)
    p.poll(T0)
    from titan_gate.verify import _verify_chain
    import tempfile, os
    fd, pp = tempfile.mkstemp(suffix=".pub")
    os.write(fd, pub.public_bytes_raw().hex().encode()); os.close(fd)
    try:
        assert _verify_chain(str(asm.receipts_root), None, pp,
                             "json", True) == 0
    finally:
        os.unlink(pp)
