"""ChainAssembler (WO-6): normalized events -> growing TRS-2 v2 chain,
with FR-ING-6 gap detection derived from the chain itself.

Design decisions (logged):
- prev/seq come ONLY from chain state. Every poll calls
  latest_receipt_hash() first, which validates the ENTIRE tree and
  hard-errors on tamper/fork — extending a broken chain would launder
  the break, so refusal is inherited, not implemented here.
- THE CHAIN IS THE STATE. No side files, no pointers, no in-memory
  flags that survive restarts: an open gap is "a gap receipt with no
  later marker," discovered by scan. A restarted assembler therefore
  cannot double-emit an open gap — the property is structural.
- No key defaults (WO-7 ledger): sign_fn=None refuses at construction.
- Last-activity definition: max over action receipts' event.ingest_time
  and marker receipts' gap.interval_end. Open-gap receipts are NOT
  activity — they record its absence.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from titan_gate.chain_state import GENESIS, latest_receipt_hash
from titan_gate.trs2_writer import build_trs2_receipt_v2

__all__ = ["ChainAssembler", "AssemblerError"]


class AssemblerError(ValueError):
    """Assembler misconfiguration or invalid poll input."""


def _t(s: str) -> datetime:
    try:
        dt = datetime.fromisoformat(s)
    except (ValueError, TypeError) as e:
        raise AssemblerError(f"invalid ISO-8601 time {s!r}: {e}") from e
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class ChainAssembler:
    def __init__(self, *, receipts_root, tenant_id: str, source_id: str,
                 key_id: str, sign_fn, silence_threshold_s: int = 600):
        if sign_fn is None:
            raise AssemblerError(
                "sign_fn is required — no key defaults, ever: an assembler "
                "that can write unsigned or default-key receipts produces "
                "records worth less than no records (WO-7 ledger)")
        for name, v in (("tenant_id", tenant_id), ("source_id", source_id),
                        ("key_id", key_id)):
            if not isinstance(v, str) or not v:
                raise AssemblerError(f"{name} must be a non-empty string")
        self.receipts_root = Path(receipts_root)
        self.tenant_id = tenant_id
        self.source_id = source_id
        self.key_id = key_id
        self._sign_fn = sign_fn
        self.silence_threshold_s = int(silence_threshold_s)

    # -- chain-derived state (recomputed every poll; never cached) --

    def _scan(self):
        """Validate tree (via latest_receipt_hash) and derive semantics.
        Returns (head_hash, next_seq, last_activity: datetime|None,
        open_gap_start: str|None)."""
        head = latest_receipt_hash(self.receipts_root)  # raises on tamper
        receipts = []
        if self.receipts_root.exists():
            for p in sorted(self.receipts_root.rglob("*.json")):
                receipts.append(json.loads(p.read_text(encoding="utf-8")))
        receipts.sort(key=lambda r: r["seq"])
        next_seq = (receipts[-1]["seq"] + 1) if receipts else 0
        last_activity = None
        open_gap_start = None
        for r in receipts:
            rt = r.get("receipt_type")
            if rt == "action":
                t = _t(r["event"]["ingest_time"])
                last_activity = max(last_activity, t) if last_activity else t
            elif rt == "gap":
                open_gap_start = r["gap"]["interval_start"]
            elif rt == "marker":
                open_gap_start = None
                t = _t(r["gap"]["interval_end"])
                last_activity = max(last_activity, t) if last_activity else t
        return head, next_seq, last_activity, open_gap_start

    def _write(self, receipt: dict) -> Path:
        self.receipts_root.mkdir(parents=True, exist_ok=True)
        p = self.receipts_root / f"{receipt['seq']:06d}.json"
        p.write_text(json.dumps(receipt, ensure_ascii=False),
                     encoding="utf-8")
        return p

    def _emit(self, *, receipt_type, prev, seq, **content) -> dict:
        return build_trs2_receipt_v2(
            receipt_type=receipt_type, tenant_id=self.tenant_id, seq=seq,
            prev_receipt_hash=prev, sign_fn=self._sign_fn,
            key_id=self.key_id, **content)

    # ------------------------------------------------------- public API

    def record_poll(self, poll_time: str, events: list) -> list:
        """One poll cycle. Returns the list of Paths written (in order)."""
        poll_dt = _t(poll_time)
        head, seq, last_activity, open_gap_start = self._scan()
        written = []

        if events:
            if open_gap_start is not None:
                r = self._emit(receipt_type="marker", prev=head, seq=seq,
                               gap={"source_id": self.source_id,
                                    "interval_start": open_gap_start,
                                    "interval_end": poll_time})
                written.append(self._write(r))
                head, seq = r["receipt_hash"], seq + 1
            for ev in events:
                r = self._emit(receipt_type="action", prev=head, seq=seq,
                               event=ev)
                written.append(self._write(r))
                head, seq = r["receipt_hash"], seq + 1
            return written

        # Empty poll: silence handling. Never double-open; no baseline,
        # no gap (an empty tree has no activity to be silent FROM).
        if open_gap_start is None and last_activity is not None:
            silent_s = (poll_dt - last_activity).total_seconds()
            if silent_s > self.silence_threshold_s:
                r = self._emit(receipt_type="gap", prev=head, seq=seq,
                               gap={"source_id": self.source_id,
                                    "interval_start":
                                        last_activity.isoformat()})
                written.append(self._write(r))
        return written
