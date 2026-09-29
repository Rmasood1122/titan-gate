#!/usr/bin/env python3
"""
label.py -- builds golden_set_size_owned. The first reachable scoreboard blank.

Reads unlabeled cases from a JSONL, asks you for a verdict on each, and writes
labels to evals/golden/labels.jsonl. Resumable: already-labeled ids are skipped,
so you can stop and come back.

    python3 evals/label.py --status
    python3 evals/label.py                       # label interactively
    python3 evals/label.py --seal                # freeze a holdout, hash it

The holdout is the tripwire for the rubric-tuning gaming vector. --seal splits
20% of labels into labels.holdout.jsonl and writes a sha256 to holdout.sha256.
`--verify-seal` fails if the holdout changed after sealing, which is what stops
kappa from being tuned against the set it is scored on.
"""

import argparse
import hashlib
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "cases.jsonl")
GOLDEN = os.path.join(HERE, "golden")
LABELS = os.path.join(GOLDEN, "labels.jsonl")
HOLDOUT = os.path.join(GOLDEN, "labels.holdout.jsonl")
SEAL = os.path.join(GOLDEN, "holdout.sha256")
FLOOR = 100
HOLDOUT_FRAC = 0.20
VALID = {"PASS", "FAIL", "SKIP"}


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def append_jsonl(path, row):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(row) + "\n")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def case_id(c, i):
    return str(c.get("id", i))


def cmd_status():
    cases = read_jsonl(CASES)
    labels = [r for r in read_jsonl(LABELS) if r.get("label") in ("PASS", "FAIL")]
    counts = {}
    for r in labels:
        counts[r["label"]] = counts.get(r["label"], 0) + 1
    print(f"cases available  : {len(cases)}   ({CASES})")
    print(f"labeled          : {len(labels)} / {FLOOR} floor")
    print(f"class balance    : {counts or '{}'}")
    if labels:
        top = max(counts.values()) / len(labels)
        print(f"majority class   : {top:.0%}" + ("  <-- WARN: skewed, kappa will be unstable" if top > 0.9 else ""))
    sealed = os.path.exists(SEAL)
    print(f"holdout sealed   : {sealed}")
    at_floor = len(labels) >= FLOOR
    print("GATE golden_set_size_owned: " + ("PASS" if at_floor else f"BLOCKED, need {FLOOR - len(labels)} more"))
    return 0 if at_floor else 1


def cmd_label(limit):
    cases = read_jsonl(CASES)
    if not cases:
        sys.exit(
            f"no cases at {CASES}\n"
            "Write one JSON object per line, each with an 'id' and whatever the\n"
            "judge will see. Minimum: {\"id\": \"c1\", \"input\": \"...\", \"output\": \"...\"}"
        )
    done = {r["id"] for r in read_jsonl(LABELS)}
    todo = [(i, c) for i, c in enumerate(cases) if case_id(c, i) not in done]
    if not todo:
        print("every case is already labeled.")
        return 0
    if limit:
        todo = todo[:limit]
    print(f"{len(todo)} to go. PASS / FAIL / SKIP, or 'q' to stop (progress is saved).\n")
    for i, c in todo:
        cid = case_id(c, i)
        print("-" * 60)
        print(f"[{cid}] " + json.dumps({k: v for k, v in c.items() if k != "id"}, indent=2)[:1200])
        while True:
            v = input("label> ").strip().upper()
            if v in ("Q", "QUIT"):
                print("stopped. rerun to continue.")
                return 0
            if v in VALID:
                break
            print(f"one of {sorted(VALID)}, or q")
        append_jsonl(LABELS, {"id": cid, "label": v})
    return cmd_status()


def cmd_seal(seed):
    labels = [r for r in read_jsonl(LABELS) if r.get("label") in ("PASS", "FAIL")]
    if len(labels) < FLOOR:
        sys.exit(f"refusing to seal: {len(labels)} labels, floor is {FLOOR}")
    if os.path.exists(SEAL):
        sys.exit(f"already sealed ({SEAL}). Delete it deliberately if you mean to reseal.")
    rng = random.Random(seed)
    idx = list(range(len(labels)))
    rng.shuffle(idx)
    n_hold = max(1, int(len(labels) * HOLDOUT_FRAC))
    hold_ids = {labels[i]["id"] for i in idx[:n_hold]}
    with open(HOLDOUT, "w") as fh:
        for r in labels:
            if r["id"] in hold_ids:
                fh.write(json.dumps(r) + "\n")
    digest = sha256_file(HOLDOUT)
    with open(SEAL, "w") as fh:
        fh.write(digest + "\n")
    print(f"sealed {n_hold} of {len(labels)} into {HOLDOUT}")
    print(f"sha256 {digest}")
    print("kappa must now be reported as kappa_dev and kappa_holdout separately.")
    return 0


def cmd_verify_seal():
    if not os.path.exists(SEAL):
        sys.exit("no seal to verify; run --seal first")
    want = open(SEAL).read().strip()
    got = sha256_file(HOLDOUT)
    if want != got:
        print(f"FAIL: holdout changed after sealing\n  sealed {want}\n  now    {got}")
        return 1
    print("PASS: holdout unchanged since sealing")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--status", action="store_true")
    p.add_argument("--seal", action="store_true")
    p.add_argument("--verify-seal", action="store_true")
    p.add_argument("--limit", type=int, default=0, help="label at most N this sitting")
    p.add_argument("--seed", type=int, default=1729, help="holdout split seed, recorded so the split is reproducible")
    a = p.parse_args()
    if a.status:
        sys.exit(cmd_status())
    if a.seal:
        sys.exit(cmd_seal(a.seed))
    if a.verify_seal:
        sys.exit(cmd_verify_seal())
    sys.exit(cmd_label(a.limit))


if __name__ == "__main__":
    main()
