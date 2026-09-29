#!/usr/bin/env python3
"""
predict.py -- the prediction log. R6's append path.

v1.1 calls the prediction log "the real output of this system", requires >= 10
completed entries to declare the design phase done, and shipped no file that
writes one. This is that file.

    python3 evals/predict.py ask "how many files under evals/ exist today?"
    python3 evals/predict.py ask "..." --prediction "12"     # non-interactive
    python3 evals/predict.py record 3 --actual "7"
    python3 evals/predict.py status

An entry is COMPLETE only when prediction and actual are both non-empty.
Only complete entries count toward the stop condition.
"""

import argparse
import json
import os
import sys
from datetime import date

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prediction_log.jsonl")
FLOOR = 10


def load():
    if not os.path.exists(LOG):
        return []
    with open(LOG) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def save(rows):
    with open(LOG, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def complete(rows):
    return [r for r in rows if str(r.get("prediction", "")).strip() and str(r.get("actual", "")).strip()]


def cmd_ask(args):
    rows = load()
    prediction = args.prediction
    if prediction is None:
        if not sys.stdin.isatty():
            sys.exit("no --prediction given and stdin is not a terminal; refusing to log a blank")
        print(f"\nQ: {args.question}")
        print("Answer before you look. 'I don't know' is a complete answer. Empty is not.")
        prediction = input("prediction> ").strip()
    if not prediction:
        sys.exit("empty prediction refused (R6: a non-answer is not an answer)")
    entry = {
        "id": len(rows) + 1,
        "date": date.today().isoformat(),
        "question": args.question,
        "prediction": prediction,
        "actual": "",
        "surprised": None,
    }
    rows.append(entry)
    save(rows)
    print(f"logged #{entry['id']}. record the actual with: python3 evals/predict.py record {entry['id']} --actual '...'")


def cmd_record(args):
    rows = load()
    hit = [r for r in rows if r["id"] == args.id]
    if not hit:
        sys.exit(f"no entry #{args.id}")
    r = hit[0]
    if not str(r.get("prediction", "")).strip():
        sys.exit(f"entry #{args.id} has no prediction; you cannot record an actual against nothing")
    r["actual"] = args.actual
    if args.surprised is None:
        r["surprised"] = str(r["prediction"]).strip().lower() != str(args.actual).strip().lower()
    else:
        r["surprised"] = args.surprised
    save(rows)
    print(f"#{args.id} prediction={r['prediction']!r} actual={r['actual']!r} surprised={r['surprised']}")


def cmd_status(args):
    rows = load()
    done = complete(rows)
    surprises = [r for r in done if r.get("surprised")]
    print(f"entries          : {len(rows)}")
    print(f"complete         : {len(done)} / {FLOOR} required by stop_conditions")
    if done:
        rate = 100.0 * len(surprises) / len(done)
        print(f"surprise rate    : {rate:.0f}%  ({len(surprises)} of {len(done)})")
    open_ids = [r["id"] for r in rows if r not in done]
    if open_ids:
        print(f"awaiting actual  : {open_ids}")
    print("GATE: " + ("PASS" if len(done) >= FLOOR else f"BLOCKED, need {FLOOR - len(done)} more"))
    return 0 if len(done) >= FLOOR else 1


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("ask", help="log a question and a prediction, before measuring")
    a.add_argument("question")
    a.add_argument("--prediction", default=None)
    a.set_defaults(func=cmd_ask)

    r = sub.add_parser("record", help="fill in what actually happened")
    r.add_argument("id", type=int)
    r.add_argument("--actual", required=True)
    r.add_argument("--surprised", type=lambda s: s.lower() == "true", default=None)
    r.set_defaults(func=cmd_record)

    s = sub.add_parser("status", help="count complete entries against the stop condition")
    s.set_defaults(func=cmd_status)

    args = p.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
