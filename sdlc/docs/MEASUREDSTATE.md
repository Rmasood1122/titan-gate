# MEASURED STATE — Rehan

Single source of truth for this project. Rule: **nothing enters this file
unless it was run and the output pasted back.** Remembered numbers get
marked UNVERIFIED until re-measured.

Last verified: 2026-08-16. Updated: 2026-08-17.

---

## 1. titan-gate — measured

| Fact | Value | How measured |
|---|---|---|
| Tests total | **842** | `pytest` after fix |
| Under `tests/` before fix | 831 | `pytest tests/ -q` |
| Crypto tests outside every count | 11 | found at repo root |
| Mutation `>=` → `>` catch rate | **0% of 829** | manual mutant |
| semantic_judge score range | 0.55–0.78 | direct calls |
| `""` (empty input) score | 0.70 = exact PASS | direct call |

Prior quotes of "840" and "305" were memory, not measurement.

**Bugs found and fixed**

- **REPO_ROOT** (test_wo2_chain.py:32) computed the *file's* dir, not the
  repo root. Invisible for months because the wrong assumption happened to
  be true in the one place it stood. Fixed.
- **Boundary blind spot.** `comp >= SCORE_PASS` → `>` survived all 829
  tests. Extracted `classify(comp, hv)` out of `evaluate()`; added exact
  boundary tests at SCORE_PASS=0.70 and SCORE_WARN=0.40. Mutant now dies.
  Committed.
- **semantic_judge is not semantic.** Pure keyword scoring, zero model
  calls. Empty/whitespace now → 0.0. The field name `semantic_score` sits
  inside the SIGNED body — renaming needs a CONTRACT_VERSION bump and
  invalidates every prior receipt hash. Deferred, not forgotten.
- 11 crypto tests moved into `tests/`.
- Pre-commit hook runs the full suite and blocks on failure. Works.

**Not measured on titan-gate:** mutmut full run; cost per receipt.

---

## 2. AIVIS — measured

- `src/aivis/scorer.py` is **19 lines**, not the 1090 remembered.
- Return-order swap mutant: caught by **1 of 6** tests (17%).
- Tests need `PYTHONPATH=src` — not clean-shell reproducible.
- Fixed: `Scores` NamedTuple so position swaps stop compiling.
- 23 tests pass.

## 3. Everything else — UNMEASURED

| Product | Convs | Measurement |
|---|---|---|
| AgentRepEngine | 271 | **none, ever** |
| ZROS | 254 | **none, ever** |
| evidence-verify | — | none |
| CalendarHarvest | — | none |

Highest-volume work, zero evidence. 22 git repos under `~/01-Projects`
(the earlier "no version control" claim was wrong — corrected on evidence).

---

## 4. Technique lift — his own 201 days of data

1,019 conversations, 14,984 of his prompts. Baseline execution rate 13.3%.

| Technique | Lift | Convs |
|---|---|---|
| XML | **5.17x** | 121 |
| Schema | 3.73x | — |
| Versioning | 3.47x | — |
| Rubric | 3.09x | — |
| Verification | 2.88x | — |
| Delegation | 2.79x | — |
| Decomposition | 2.73x | — |
| Audit | 2.63x | — |
| Quantified | 2.01x | — |
| Hard rules | 1.91x | — |
| Persona | 1.68x | — |
| **Meta-prompting** | **1.48x** | **321** |
| **Red-team** | **0.74x** (below baseline) | — |

Meta-prompting is his #2 most-used technique and his weakest return.
XML is 3.5x better and he uses it a third as often.

- Few-shot: **6 uses in 14,984 prompts.**
- Zero uses: self-consistency, abstention token, anchored judge, prompt
  chaining, order-bias control, cost accounting, contrastive negatives.
- Depth collapsed: median human turns/conv was **19 in Feb 2026, 2 in
  May–June**. 44% of all conversations end within 2 turns.
- Google Drive check (2026-08-17): 20+ meta-prompt / framework / SWOT
  docs, several exact duplicates. Zero measurement artifacts. The 1.48x
  is visible in the file listing.

**Market screens** (convs / executed): eval design 57/36 PARTIAL ·
tracing 95/48 · latency 86/40 · agent orchestration 49/22 · injection
defense 42/18 · RAG 122/38 · MCP 20/7 · **cost budget 25/1 NOT
DEMONSTRATED**.

---

## 5. Kill test — LIVE, expires 2026-08-23

- **Assumption:** agency owners shipping AI-written code need
  proof-of-review artifacts for clients.
- **Evidence bar:** ≥2 substantive replies, ANY channel.
- **Status:** 5 DMs sent 2026-08-16. <2 replies → distinguish *channel*
  problem from *demand* problem before concluding anything.
- **Ahmad:** agreed verbally to be named backup engineer. **Not signed.**
  Signature converts 4 factors (SLA, bus factor, implementation support,
  maintenance). Verbal ≠ procurement-acceptable.
- **Capital:** $5,000 now, $30,000 arrangeable. SOC 2 Type I ~$15k.
  Do not spend before demand evidence exists.

---

## 6. Lessons done

L1 test your test (eval harness 0.681 → label auditing) · L2 the loop ·
L3 fix the right layer · L4 read code you didn't write (AIVIS scorer) ·
L5 make bugs unrepresentable (NamedTuple).

**Technique curriculum done:** T01 persona, T02 XML, T03 hard rules,
T04 few-shot, T05 schema, T06 decomposition, T07 verification, T08
red-team, T09 rubric, T10 meta-prompting, T11 versioning, T12 audit,
T22 quantified, T23 delegation, M6 golden sets, M7 judge, M8 regression,
M9 citation, M11 chaining, M12 order-bias, M14 cost accounting.

**Remaining:** M2 contrastive negatives, M4 self-consistency,
M5 abstention.

---

## 7. Open work — dependency order

- **A. (5 min, phone)** Name ONE warm contact who'd actually reply. The
  kill test is otherwise measuring a dead channel. *Blocked on nothing.*
- **B. (1 evening)** Golden set: 25 files from his repos, **he** labels
  PASS/FAIL, no AI. Floor under every later measurement. *Blocked on
  nothing.*
- **C. (1–2 hrs)** Cost instrumentation on titan-gate: tokens + $ per
  receipt. Cheapest fix for the screen he fails hardest (25/1).
- **D. (<1 hr each)** Few-shot exemplars · abstention token replacing
  bare `except` · contrastive negatives in rubrics · prefill `{` on JSON.
- **E. (1–2 days, needs B)** Anchored judge + validation. Cohen's kappa
  with Wilson CI — **not raw agreement**, which inflates under class
  imbalance. Gate: κ≥0.6 provisional, ≥0.75 ship.
- **F. (2–3 hrs)** AgentRepEngine: `go test ./...`, then 10 known cases.
- **G.** mutmut on titan-gate. Triage survivors into killable vs
  equivalent with a one-line proof each. Catch rate over KILLABLE only.

---

## 8. Spaced-repetition bank

Ask one per session. Hold until **he** answers — a pasted AI answer
deletes the retrieval the question exists to create.

1. Why did the REPO_ROOT bug stay invisible for months?
   → Its wrong assumption happened to be true in the one place it stood.
2. What single input value kills the `>=` → `>` mutant? → Exactly 0.70.
3. Why must an uncited sentence be deleted, not marked unverified?
   → A marked claim still gets read. Deletion is the only real filter.
4. What does an aggregate score hide that a per-case diff exposes?
   → Offsetting damage: 6 up, 4 down still averages positive.
5. What does a judge prefer when the same pair flips on order swap?
   → Position, not quality.

---

## 9. Habits — counts from one session

| Habit | Count | Cost |
|---|---|---|
| Stray leading char on paste ("cgrep", "cgit", "q") | 6 | seconds |
| Re-runs stale command instead of reading output on screen | 6 | the answer was already there |
| Pastes another AI's reply as his own answer | 3 | deletes the retrieval |
| Quotes remembered numbers (840, 1090, 305) | 4 | this whole file exists to fix it |

**Strength worth protecting:** he abandons a wrong position within one
exchange when shown evidence. Five times in one session. This is rare and
it is the reason measurement works on him at all.

---

## 10. Banned in this project

No "24x". No "top 1%". No percentiles — no population exists to rank
against. Untested is stated as untested.
