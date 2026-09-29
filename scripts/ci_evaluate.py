#!/usr/bin/env python3
import argparse
import json
import os
import sys
import subprocess
import pathlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from judge_engine.v1.engine import evaluate
from titan_gate.chain_state import latest_receipt_hash


def get_changed_files(base_branch):
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"origin/{base_branch}...HEAD"],
            capture_output=True, text=True, check=True
        )
        return [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]
    except Exception:
        return []


def get_artifact(changed_files):
    parts = []
    for path in changed_files[:10]:
        if os.path.exists(path) and path.endswith(".py"):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read(4000)
                parts.append(f"# FILE: {path}\n{content}")
            except Exception:
                pass
    return "\n\n".join(parts) if parts else "# No Python files changed"


def save_receipt(receipt, output_arg):
    """
    Save receipt to two locations:
      1. .titan/receipts/{root_date}/{receipt_id}.json  (canonical chain location)
      2. --output path (default: receipt.json)          (GitHub Actions artifact)
    """
    receipt_id = receipt.get("receipt_id", "unknown")
    root_date = receipt.get("root_date", "unknown")

    # Canonical chain path
    chain_path = pathlib.Path(".titan") / "receipts" / root_date / f"{receipt_id}.json"
    chain_path.parent.mkdir(parents=True, exist_ok=True)
    with open(chain_path, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2)
    print(f"Receipt chained: {chain_path}")

    # Artifact path for GitHub Actions upload
    artifact_path = pathlib.Path(output_arg)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    with open(artifact_path, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2)
    print(f"Receipt saved  : {artifact_path}")

    return chain_path


def post_pr_comment(token, repo, pr_number, receipt):
    if not token:
        return
    try:
        import urllib.request
        verdict = receipt.get("verdict", "UNKNOWN")
        score = receipt.get("composite_score", 0)
        receipt_id = receipt.get("receipt_id", "unknown")
        receipt_hash = receipt.get("receipt_hash", "")[:16]
        hv = receipt.get("hard_violations", [])
        pv = receipt.get("process_violations", [])

        emoji = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌"}.get(verdict, "❓")

        body = f"""## {emoji} Titan Gate Evaluation

| Field | Value |
|-------|-------|
| Verdict | **{verdict}** |
| Score | {score} |
| Receipt ID | `{receipt_id}` |
| Receipt Hash | `{receipt_hash}...` |

"""
        if hv:
            body += "### Hard Violations\n"
            for v in hv:
                body += f"- `[{v.get('code')}]` {v.get('description')}\n"
            body += "\n"
        if pv:
            body += "### Process Violations\n"
            for v in pv:
                body += f"- `[{v.get('code')}]` {v.get('description')}\n"
            body += "\n"

        body += "*Verified by [Titan Gate](https://github.com/Rehanrana11/titan-gate) — cryptographic change control*"

        data = json.dumps({"body": body}).encode()
        url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        req = urllib.request.Request(
            url, data=data,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/vnd.github+json",
            },
            method="POST"
        )
        urllib.request.urlopen(req)
        print("PR comment posted.")
    except Exception as e:
        print(f"Warning: could not post PR comment: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Titan Gate CI Evaluator")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--title", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--output", default="receipt.json")
    args = parser.parse_args()

    key = os.environ.get("TITAN_SIGNING_KEY")
    if not key:
        raise SystemExit(
            "TITAN_SIGNING_KEY not set — refusing to sign. A receipt "
            "under a known-default key is worse than no receipt (Rule 1).")
    token = os.environ.get("GITHUB_TOKEN", "")

    changed_files = get_changed_files(args.base)
    print(f"Changed files: {changed_files}")

    artifact = get_artifact(changed_files)
    scope = {
        "files": changed_files,
        "language": "python",
        "pr_number": args.pr,
    }

    receipt = evaluate(
        artifact=artifact,
        scope=scope,
        tenant_id=args.tenant,
        repo=args.repo.split("/")[-1],
        repo_full_name=args.repo,
        pr_number=args.pr,
        pr_title=args.title,
        branch=args.branch,
        base_branch=args.base,
        commit_sha=args.sha,
        key_hex=key,
        prev_receipt_hash=latest_receipt_hash(pathlib.Path(".titan") / "receipts"),
    )

    chain_path = save_receipt(receipt, args.output)

    verdict = receipt.get("verdict")
    score = receipt.get("composite_score")
    receipt_id = receipt.get("receipt_id")

    print(f"Verdict      : {verdict}")
    print(f"Score        : {score}")
    print(f"Receipt ID   : {receipt_id}")

    post_pr_comment(token, args.repo, args.pr, receipt)

    if verdict == "FAIL":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()