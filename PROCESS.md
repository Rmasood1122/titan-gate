# PROCESS.md — Titan Gate Build Discipline v1.1
**August 6, 2026 · Single process source of truth · Supersedes scattered
process notes in continuation prompts · Companion to MASTER_STATE Rules 1–6**
**Ancestry: distilled from ZROS v2.8 (ARE) — mostly as a negative specimen.**

---

## §1 THE INVERSION (read this first, every hire, every session)

ARE ran 19 process gates, 4 hard stops, and a per-session checklist for
months. Its tamper-evidence gate was `curl /health | jq .hash_chain_valid`
— the system self-reporting its own integrity. The 24-probe audit found:
hash covering 5/12 columns, prev_hash stored but never verified, a live
tamper leaving the hash intact, Merkle core at 0% coverage. Every gate
passed while the load-bearing claim was false.

**ZROS gates asked "does the check exist?" Titan gates ask "does the
attack fail?"** Presence-checks are verification theater. The only
admissible evidence for a property is an adversarial test that mutates,
deletes, reorders, forges, or relabels — and must FAIL, with position.
probe_24 caught P11 this way. No health endpoint ever would have.

## §2 INCIDENT REGISTER (incident → root cause → rule → mechanical guard)

| # | Incident | Root cause | Standing rule | Guard |
|---|---|---|---|---|
| TG-1 | Terminal paste replayed scrollback as commands; destroyed uncommitted file | Output pasted back into terminal | Terminal output goes to chat, NEVER back into the terminal | Workflow rule (human) |
| TG-2 | Mojibake ×3 (curl fixture, bare open(), UTF-16 .gitignore) | Windows cp1252 default | Every text open() carries encoding='utf-8'; byte-writes for fetched fixtures | CI lint (queued) |
| TG-3 | Guards fired on docstrings/comments ×3 | String match ≠ call match | Guards match CALLS not strings; a fired guard means READ THE FILE | Guard patterns |
| TG-4 | promote_anchor defined below __main__ guard; import tests structurally blind | Import-based testing gap | Script-mode subprocess smoke is a required test class | def-order lint + smoke test (cd98a7f) |
| TG-5 | Wire divergence ×4 (ECDSA checkpoints, Prehashed, verbatim-body-leaf, mojibake) | Synthetic tests only prove self-consistency | Every external protocol gets one wire-truth fixture captured from the real system | Repo fixtures (live Rekor entry) |
| TG-6 | Vendor-side signing capability recurred 4× (BRD, FRD, TDD, ARE code) | Convenience pressure is convergent | No vendor-domain signer ever, including tests; no key defaults — absent key = refuse to sign | Signer-symbol lint; keyless exit 2 |
| TG-7 | Gate 0 outreach deferred across 4 work orders (= Ω1) | Building feels like progress; outreach clocks run on calendar time | Blocking decisions are agenda item #1; expert ruling / "no warm path"→scoped task are valid resolutions | D6 pattern + §4b Ω-naming |
| TG-8 | ARE: all gates green, core claim false | Presence-checks over property-attacks | §1 inversion; every claimed property has a mutating AT | Rule 2 + this file |
| TG-9 | Test asserted mechanism, not property (regex on "schema_version"; closed-set fired first) | Over-specified assertion inferred from truncated read | Assert the PROPERTY (rejection happens); pin the mechanism only when the mechanism is the spec | Test review habit |
| TG-10 | ARE's 342-line decision tribunal fired 0 times while fatal decisions passed unheard | Governance triggered on every verb; protection attached to files, not properties | Decision checks fire ONLY on irreversible/architectural acts; protection attaches to pinned properties (ATs/goldens), never files | §4b |

**Register discipline:** new incident → new row, same session, with the
guard named. A row is not closed until its guard is mechanical (lint,
test, hook) or explicitly accepted as human-procedural.

## §3 SESSION TRIAGE (one paste, session start)

```bash
cd ~/Projects/titan-gate
echo "=== SUITE ===" && python -m pytest -q 2>&1 | tail -2
echo "=== CLEAN ===" && git status --short && \
  n=$(git log origin/main..HEAD --oneline | wc -l) && echo "unpushed: $n"
echo "=== GOLDENS ===" && python -m pytest tests/ -q -k "golden or wo34" 2>&1 | tail -2
echo "=== ANCHOR ===" && python - << 'EOF'
import json
from cryptography.hazmat.primitives import serialization
from titan_gate.anchor_verify import verify_anchor_record_offline
a = json.load(open(".titan-gate/anchors/Rehanrana11/Rehanrana11_titan-gate/2026-03-06.json", encoding="utf-8"))
rec = json.load(open(a["rekor_record_path"], encoding="utf-8"))
pub = serialization.load_pem_public_key(open("tests/fixtures/rekor_log_pubkey.pem","rb").read())
verify_anchor_record_offline(rec, pub, expected_artifact_hash_hex=a["merkle_root"])
print("anchor offline re-verify: PASS")
EOF
```

All four green → build. Any red → that is the session's first task, no
exceptions. (Pre-commit hook is LOCAL-ONLY — reinstall on new machines.)

## §4 DEFINITION OF DONE — THE CORRECTED LADDER

Done = D7. D1–D6 are NOT done. (ARE's ladder measured coverage and
latency; nothing on it required an attack to fail. Corrected:)

- **D1** Failing AT exists and fails at the right symbol/assertion (red first, always)
- **D2** Implementation green on the AT
- **D3** Adversarial variants FAIL correctly: mutate, delete, reorder, forge, relabel, smuggle — with position where the spec claims position
- **D4** Golden pins untouched: legacy vectors byte-identical, old verifiers refuse new formats
- **D5** Full suite green, run by the pre-commit hook (tail pasted)
- **D6** Pushed; `TITAN CLEAN: 0 unpushed`
- **D7** Honest claim boundary updated in CONTINUATION_PROMPT (Rule 3): what is now [F], what is explicitly NOT yet claimable

## §4b PRE-IRREVERSIBLE CHECK (fires ONLY on irreversible/architectural acts:
deletions, force-push, publication, key ops, spec stabilization, WO re-order)

Three questions, no tribunal: (1) Reversible in 24h? If NO → blast radius
named in writing first. (2) Ω-pattern named or "clean": Ω1 engineering-as-
commercial-avoidance · Ω2 premature completeness · Ω3 premature complexity ·
Ω4 planning-instead-of-acting. (3) Decision logged with a PREDICTED outcome
line; predicted-vs-actual reviewed at the quarterly probe_24 run (calibration
rides an existing clock — no new ceremony).

## §5 EXPLICIT REJECTIONS (recorded so they cannot return as "optimizations")

- **Self-reported health as integrity proof** (`hash_chain_valid: true`) — the check that let ARE's broken chain pass for months. Integrity is proven only by attacks that fail.
- **grep-presence gates** ("symbol has callers ⇒ wired") — institutionalized mention-vs-use. Wiring is proven by an end-to-end AT.
- **Self-scored readiness composites** ("84/100 ENTERPRISE-READY" from a self-administered panel) — untagged [A] as certification. External parties score readiness; we ship ATs.
- **Fix-rate as primary metric** — measures churn, invites commit-relabeling, says nothing about truth. Rule 2 (nothing claimed until its AT passes) is the metric.
- **Checklist accretion** — ZROS grew 3 laws/5 incidents/3 gates per version while its fatal defect passed every gate. Depth over count: this file stays ≤150 lines; growth requires removal.
- **Fail-open identity checks** — trust decisions fail closed; only non-trust infrastructure fails open. ARE's /verify failed open on timeout: forged tokens pass during downtime.
- **Sacred-file rules** — ARE declared its (broken) hash chain "sacred"; untouchability entrenched the defect. Pin properties, never files.
- **Simulated-panel validation** — labeled expert voices may break a founder deadlock (TG-7); they never validate a claim. Attacks validate.

## §6 REMOVAL REVIEW (the law ZROS wrote and never obeyed)

Quarterly (with the probe_24 scheduled run): any register row whose guard
has not fired in 90 days, and any rule in this file, gets reviewed for
removal or demotion. A rule kept "just in case" is weight; weight is how
checklists replace thinking. This file shrinking is a health signal.

---
*v1.1 · Lines: ~160 (over 150: two rows earn removal at next quarterly review) · Grows only by incident, shrinks by review.*
