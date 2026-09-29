"""CopilotPoller (WO-6): fetch seam -> normalize -> dedup -> chain.

The seam is fetch_fn(window_start, window_end) -> list[dict] of raw
audit records. The real Management Activity API client (auth, content
blobs, paging) implements this signature later; everything below the
seam is proven against wire-truth fixtures. Honest boundary (Rule 3):
[F] below the seam, [A] at the wire until a real tenant runs it.

Design decisions (logged):
- Mixed feeds are reality: non-CopilotInteraction records are SKIPPED
  and counted, never errors. A 261 record that fails normalization is
  REJECTED and counted; the poll continues — one bad record must not
  silence a source (FR-ING-3 rejection-class pattern).
- Dedup: THE CHAIN IS THE STATE (FR-ING-4 for this path). Already-
  receipted source_event_ids are discovered by chain scan and skipped,
  so overlapping poll windows — the safe way to poll — cannot inflate
  the chain. No side store to lose.
- Fetch failure = silence, disclosed: a raising fetch_fn yields
  empty-poll semantics with fetch_error recorded; sustained failure
  crosses the assembler's threshold and becomes a SIGNED gap receipt.
  Fail-stop: less recording, fully disclosed.
- No clock in this module: `now` is caller-supplied, like ingest_time.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from titan_gate.copilot_normalize import (
    normalize_copilot_record, CopilotNormalizeError,
    COPILOT_RECORD_TYPE, COPILOT_OPERATION)

__all__ = ["CopilotPoller", "PollReport"]


@dataclass
class PollReport:
    """Per-poll accounting — the raw material for M4/UC-7 coverage."""
    fetched: int = 0
    skipped_other_type: int = 0
    rejected: int = 0
    deduped: int = 0
    receipted: int = 0
    fetch_error: str | None = None


def _t(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class CopilotPoller:
    def __init__(self, *, fetch_fn, assembler, window_overlap_s: int = 60):
        if fetch_fn is None:
            raise ValueError("fetch_fn is required")
        self._fetch_fn = fetch_fn
        self._assembler = assembler
        self._overlap = timedelta(seconds=int(window_overlap_s))
        self._last_window_end: datetime | None = None

    def _already_receipted(self) -> set:
        """source_event_ids present in the chain (action receipts)."""
        seen = set()
        root = Path(self._assembler.receipts_root)
        if root.exists():
            for p in sorted(root.rglob("*.json")):
                r = json.loads(p.read_text(encoding="utf-8"))
                if r.get("receipt_type") == "action":
                    seen.add(r["event"]["source_event_id"])
        return seen

    def poll(self, now: str) -> PollReport:
        now_dt = _t(now)
        window_start = (self._last_window_end - self._overlap
                        if self._last_window_end else now_dt - self._overlap)
        report = PollReport()

        try:
            raw = list(self._fetch_fn(window_start.isoformat(),
                                      now_dt.isoformat()))
        except Exception as e:  # noqa: BLE001 — any wire failure = silence
            report.fetch_error = f"{type(e).__name__}: {e}"
            raw = []
        else:
            self._last_window_end = now_dt
        report.fetched = len(raw)

        seen = self._already_receipted()
        events = []
        for record in raw:
            if not (isinstance(record, dict)
                    and record.get("RecordType") == COPILOT_RECORD_TYPE
                    and record.get("Operation") == COPILOT_OPERATION):
                report.skipped_other_type += 1
                continue
            try:
                ev = normalize_copilot_record(
                    record, source_id=self._assembler.source_id,
                    ingest_time=now)
            except CopilotNormalizeError:
                report.rejected += 1
                continue
            if ev["source_event_id"] in seen:
                report.deduped += 1
                continue
            seen.add(ev["source_event_id"])   # in-batch dedup too
            events.append(ev)

        self._assembler.record_poll(now, events)  # empty polls accrue silence
        report.receipted = len(events)
        return report
