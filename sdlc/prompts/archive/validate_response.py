#!/usr/bin/env python3
"""
validate_response.py -- mechanical enforcement of SDLC DESIGNER v1.1 rules.

The v1 prompt claimed "eight rules, eight checks" but four of those checks
(R1 instrument state, R2 number tags, R3 citations, R4 resolving artifact)
had nowhere to land in the JSON output contract, so no stranger could run
them. This script is that landing.

Usage:
    python validate_response.py response.json
    python validate_response.py --selftest        # known-good + known-bad
    python validate_response.py response.json --lenient   # untagged numbers WARN, not FAIL

Exit code 0 = PASS, 1 = FAIL, 2 = usage error.
"""

import json
import re
import sys

VERDICTS = {"PROCEED", "REJECTED", "INSUFFICIENT_BASIS"}
BLANKS = {
    "cost_per_receipt",
    "judge_agreement_kappa",
    "mutation_catch_rate",
    "golden_set_size_owned",
    "agentrepengine_tests",
    "NONE",
}
BASES = {"measured", "EST", "INSUFFICIENT_BASIS"}

REQUIRED_KEYS = [
    "reasoning",
    "blank_filled",
    "verdict",
    "instrument_status",
    "artifacts",
    "failure_prevented",
    "techniques",
    "figures",
    "citations",
    "prediction_required_from_human",
    "gaming_vector",
    "tripwire",
    "deferred",
]

# Prose fields swept for untagged numbers (R2).
PROSE_FIELDS = [
    "reasoning",
    "failure_prevented",
    "gaming_vector",
    "tripwire",
    "prediction_required_from_human",
    "rejection_reason",
]

PLACEHOLDER_PAT = re.compile(
    r"(<[a-z_ ]+>|\{\{|\bTODO\b|\bFIXME\b|path/to|your[-_]|\.\.\.)", re.I
)
# Numeric tokens: 0.6, 75%, $1.20, 100, 1.48x, >=0.6
NUM_PAT = re.compile(r"[<>]=?\s*\$?\d[\d,]*\.?\d*\s*[%x]?|\$\d[\d,]*\.?\d*|\b\d[\d,]*\.?\d*\s*[%x]?")
# Structural references that are not claims about the world.
NUM_EXEMPT_CTX = re.compile(r"(phase\s*-?\d+|\bR\d\b|\bC\d+\b|\bv\d(\.\d)?\b|step\s*\d+)", re.I)
INLINE_TAG_PAT = re.compile(r"\[(measured:[^\]]+|EST:[^\]]+|INSUFFICIENT_BASIS)\]")
CITATION_PAT = re.compile(
    r"([\w./-]+:\d+"                      # file:line
    r"|`[^`]+`|^\$\s?\S+"                 # quoted or $-prefixed command
    r"|\b(ls|rg|grep|find|cat|wc|python3?|pytest|git|make|npm|jq|sed|awk|curl|head|tail)\b)"
)
ASSERTION_PAT = re.compile(r"(assert|blocks?\b|fail|abort|reject|[<>]=?|==|\bexit\b)", re.I)

fails, warns = [], []


def fail(code, msg):
    fails.append(f"FAIL {code}: {msg}")


def warn(code, msg):
    warns.append(f"WARN {code}: {msg}")


def numeric_tokens(text):
    out = []
    for m in NUM_PAT.finditer(text or ""):
        lo, hi = max(0, m.start() - 12), min(len(text), m.end() + 4)
        if NUM_EXEMPT_CTX.search(text[lo:hi]):
            continue
        tail = text[m.end():m.end() + 90]
        if INLINE_TAG_PAT.search(tail):
            continue
        out.append(m.group(0).strip())
    return out


def check(doc, lenient=False):
    fails.clear()
    warns.clear()

    # C1 -- required keys (makes every rule's check addressable)
    for k in REQUIRED_KEYS:
        if k not in doc:
            fail("C1", f"missing required key '{k}'")
    if fails:
        return

    # C2 -- enums
    if doc["verdict"] not in VERDICTS:
        fail("C2", f"verdict '{doc['verdict']}' not in {sorted(VERDICTS)}")
    if doc["blank_filled"] not in BLANKS:
        fail("C2", f"blank_filled '{doc['blank_filled']}' not in {sorted(BLANKS)}")

    # C3 -- scoreboard rule: an artifact filling no blank cannot PROCEED
    if doc["blank_filled"] == "NONE" and doc["verdict"] == "PROCEED":
        fail("C3", "blank_filled=NONE with verdict=PROCEED (scoreboard rule)")

    # C4 -- R8 scope ceiling, and abstention must not carry artifacts
    arts = doc["artifacts"]
    if not isinstance(arts, list):
        fail("C4", "artifacts must be a list")
        arts = []
    if len(arts) > 3:
        fail("C4", f"{len(arts)} artifacts proposed, R8 ceiling is 3")
    if doc["verdict"] == "PROCEED" and len(arts) == 0:
        fail("C4", "verdict=PROCEED with zero artifacts")
    if doc["verdict"] != "PROCEED" and len(arts) > 0:
        fail("C4", f"verdict={doc['verdict']} must carry zero artifacts, found {len(arts)}")

    # C5 -- artifacts must be runnable, not sketched
    for i, a in enumerate(arts):
        for k in ("path", "runnable_command", "expected_output"):
            if not a.get(k):
                fail("C5", f"artifacts[{i}] missing '{k}'")
        cmd = a.get("runnable_command", "")
        m = PLACEHOLDER_PAT.search(cmd)
        if m:
            fail("C5", f"artifacts[{i}].runnable_command contains placeholder '{m.group(0)}'")

    # C6 -- R2: every figure carries an origin
    for i, f in enumerate(doc["figures"]):
        if f.get("basis") not in BASES:
            fail("C6", f"figures[{i}].basis '{f.get('basis')}' not in {sorted(BASES)}")
        if f.get("basis") == "measured" and not f.get("origin_command"):
            fail("C6", f"figures[{i}] basis=measured with no origin_command")

    # C7 -- R2 grep: no number anywhere without a tag or a figures[] entry
    declared = " ".join(str(f.get("value", "")) for f in doc["figures"])
    for field in PROSE_FIELDS:
        for tok in numeric_tokens(doc.get(field, "")):
            bare = tok.lstrip("<>= ").strip()
            if bare and bare not in declared:
                (warn if lenient else fail)("C7", f"untagged number '{tok}' in {field}")
    for i, a in enumerate(arts):
        for tok in numeric_tokens(a.get("expected_output", "")):
            bare = tok.lstrip("<>= ").strip()
            if bare and bare not in declared:
                (warn if lenient else fail)(
                    "C7", f"untagged number '{tok}' in artifacts[{i}].expected_output"
                )

    # C8 -- R3: claims about his code cite file:line or a command
    for i, c in enumerate(doc["citations"]):
        if not c.get("claim"):
            fail("C8", f"citations[{i}] missing 'claim'")
        src = c.get("source", "")
        if not CITATION_PAT.search(src):
            fail("C8", f"citations[{i}].source '{src}' is not file:line or a command")

    # C9 -- R5: no technique without a named failure mode
    for i, t in enumerate(doc["techniques"]):
        if not t.get("name") or not t.get("failure_mode_it_prevents"):
            fail("C9", f"techniques[{i}] missing name or failure_mode_it_prevents")

    # C10 -- R6: a prediction must actually be asked
    p = doc["prediction_required_from_human"]
    if not p or not p.strip().endswith("?"):
        fail("C10", "prediction_required_from_human must be a question ending in '?'")

    # C11 -- R7: gaming vector and a tripwire that asserts something
    if not doc["gaming_vector"].strip():
        fail("C11", "gaming_vector is empty")
    if not doc["tripwire"].strip():
        fail("C11", "tripwire is empty")
    if doc["gaming_vector"].strip() and doc["gaming_vector"].strip() == doc["tripwire"].strip():
        fail("C11", "tripwire restates gaming_vector")
    if doc["tripwire"] and not ASSERTION_PAT.search(doc["tripwire"]):
        warn("C11", "tripwire contains no assertion-like token; may not be automated")

    # C12 -- R1: one live instrument at a time
    ins = doc["instrument_status"]
    for k in ("name", "live", "known_good_case", "known_bad_case"):
        if k not in ins:
            fail("C12", f"instrument_status missing '{k}'")
    if ins.get("live") is False and any(a.get("is_instrument") for a in arts):
        fail("C12", f"proposing a new instrument while '{ins.get('name')}' is not live (R1)")
    if ins.get("live") is True and not (ins.get("known_good_case") and ins.get("known_bad_case")):
        fail("C12", "instrument marked live without both a known-good and a known-bad case")

    # C13 -- R4: abstention must name what would resolve it
    if doc["verdict"] == "INSUFFICIENT_BASIS" and not doc.get("resolving_artifact"):
        fail("C13", "verdict=INSUFFICIENT_BASIS with no resolving_artifact named")
    if doc["verdict"] == "REJECTED" and not doc.get("rejection_reason"):
        fail("C13", "verdict=REJECTED with no rejection_reason")

    # C14 -- R8: deferred items must carry an un-defer trigger
    for i, d in enumerate(doc["deferred"]):
        if isinstance(d, dict):
            if not d.get("trigger"):
                fail("C14", f"deferred[{i}] has no un-defer trigger")
        else:
            fail("C14", f"deferred[{i}] must be an object with 'artifact' and 'trigger'")


GOOD = {
    "reasoning": "Kappa cannot be computed before a labeled set exists, so the golden set is the only reachable blank.",
    "blank_filled": "golden_set_size_owned",
    "verdict": "PROCEED",
    "instrument_status": {
        "name": "none",
        "live": True,
        "known_good_case": "n/a - no instrument live",
        "known_bad_case": "n/a - no instrument live",
    },
    "artifacts": [
        {
            "path": "evals/golden/labels.jsonl",
            "runnable_command": "python evals/label_cli.py --n 100 --out evals/golden/labels.jsonl",
            "expected_output": "wrote 100 labeled rows [EST: one sitting]",
            "is_instrument": False,
        }
    ],
    "failure_prevented": "Judge kappa was reported against a set that was edited after the judge saw it.",
    "techniques": [
        {"name": "sealed holdout", "failure_mode_it_prevents": "rubric tuned until dev kappa rises"}
    ],
    "figures": [
        {"value": "100", "basis": "EST", "origin_command": ""},
        {"value": "20%", "basis": "EST", "origin_command": ""},
    ],
    "citations": [{"claim": "no labels exist yet", "source": "ls evals/golden/"}],
    "prediction_required_from_human": "How many of the 100 will you label PASS?",
    "gaming_vector": "Labeling only easy cases so agreement looks high later.",
    "tripwire": "assert stratified sample: 20% of rows drawn from prior failures, else exit 1",
    "deferred": [{"artifact": "prediction_log.jsonl", "trigger": "first measurement is run"}],
}

BAD = {
    "reasoning": "This is foundational work that enables later phases.",
    "blank_filled": "NONE",
    "verdict": "PROCEED",
    "instrument_status": {
        "name": "judge_v0",
        "live": False,
        "known_good_case": "",
        "known_bad_case": "",
    },
    "artifacts": [
        {
            "path": "evals/judge.py",
            "runnable_command": "python evals/judge.py --input <path/to/cases>",
            "expected_output": "kappa around 0.75 or better",
            "is_instrument": True,
        },
        {"path": "a.py", "runnable_command": "python a.py", "expected_output": "ok"},
        {"path": "b.py", "runnable_command": "python b.py", "expected_output": "ok"},
        {"path": "c.py", "runnable_command": "python c.py", "expected_output": "ok"},
    ],
    "failure_prevented": "Poor evaluation quality.",
    "techniques": [{"name": "chain of thought", "failure_mode_it_prevents": ""}],
    "figures": [],
    "citations": [{"claim": "his judge is unanchored", "source": "probably"}],
    "prediction_required_from_human": "Think about what the result will be.",
    "gaming_vector": "",
    "tripwire": "",
    "deferred": ["a second repo"],
}


def run(doc, label, expect_pass, lenient=False):
    check(doc, lenient=lenient)
    ok = not fails
    for line in fails + warns:
        print(f"  {line}")
    status = "PASS" if ok else "FAIL"
    verdict = "as expected" if ok == expect_pass else "UNEXPECTED"
    print(f"  -> {label}: {status} ({verdict}, {len(fails)} fail / {len(warns)} warn)\n")
    return ok == expect_pass


def main():
    args = [a for a in sys.argv[1:]]
    lenient = "--lenient" in args
    args = [a for a in args if not a.startswith("--")]

    if "--selftest" in sys.argv[1:]:
        print("selftest: known-good fixture")
        a = run(GOOD, "known-good", True, lenient)
        print("selftest: known-bad fixture")
        b = run(BAD, "known-bad", False, lenient)
        print("SELFTEST PASS" if a and b else "SELFTEST FAIL")
        return 0 if (a and b) else 1

    if not args:
        print(__doc__)
        return 2
    with open(args[0]) as fh:
        doc = json.load(fh)
    check(doc, lenient=lenient)
    for line in fails + warns:
        print(line)
    print("PASS" if not fails else f"FAIL ({len(fails)} violations)")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
