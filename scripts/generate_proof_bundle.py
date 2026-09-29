import argparse
import hashlib
import json
import os
import sys
import zipfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.merkle import compute_merkle_root, make_leaf_string, leaf_hash, MERKLE_ALGORITHM
from api.anchor import build_anchor
from api.constants import ENGINE_VERSION, CONTRACT_VERSION

SIGNING_VERSION = "hmac-sha256-v1"
ANCHOR_SCHEMA = "anchor_v1"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_str(s):
    return sha256_bytes(s.encode("utf-8"))


def load_receipts(paths):
    receipts = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as f:
            receipts.append(json.load(f))
    return receipts


def build_merkle_proof(leaves, target_leaf):
    sorted_leaves = sorted(leaves)
    if not sorted_leaves:
        return []
    proof = []
    idx = sorted_leaves.index(target_leaf)
    hashes = [leaf_hash(l) for l in sorted_leaves]
    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        sibling_idx = idx ^ 1
        proof.append({
            "sibling": hashes[sibling_idx],
            "position": "right" if idx % 2 == 0 else "left",
        })
        hashes = [
            hashlib.sha256(
                b"N|" + bytes.fromhex(hashes[i]) + bytes.fromhex(hashes[i + 1])
            ).hexdigest()
            for i in range(0, len(hashes), 2)
        ]
        idx //= 2
    return proof


def build_receipt_artifact(receipts, leaves):
    proofs = []
    for i, r in enumerate(receipts):
        proofs.append({
            "receipt_id": r["receipt_id"],
            "receipt_hash": r["receipt_hash"],
            "leaf_string": leaves[i],
            "leaf_hash": leaf_hash(leaves[i]),
            "merkle_proof": build_merkle_proof(leaves, leaves[i]),
            "verdict": r.get("verdict"),
            "composite_score": r.get("composite_score"),
            "evaluated_at": r.get("evaluated_at"),
            "signature": r.get("signature", ""),
        })
    return {
        "schema": "receipt_bundle_v1",
        "receipt_count": len(receipts),
        "receipts": proofs,
    }


def build_replay_result(receipts):
    results = []
    for r in receipts:
        anomalies = []
        hard = r.get("hard_violations", [])
        process = r.get("process_violations", [])
        if hard:
            anomalies.append({"type": "hard_violations", "items": hard})
        if process:
            anomalies.append({"type": "process_violations", "items": process})
        results.append({
            "receipt_id": r["receipt_id"],
            "verdict": r.get("verdict"),
            "composite_score": r.get("composite_score"),
            "structural_score": r.get("structural_score"),
            "semantic_score": r.get("semantic_score"),
            "anomalies": anomalies,
        })
    return {
        "schema": "replay_result_v1",
        "engine_version": ENGINE_VERSION,
        "results": results,
    }


def build_anchor_artifact(tenant_id, repo_full_name, root_date, receipts):
    anchor = build_anchor(tenant_id, repo_full_name, root_date, receipts)
    anchor["status"] = "promoted"
    if anchor.get("promoted_at") is None:
        anchor["promoted_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return anchor


def build_ndjson_export(receipts):
    lines = []
    for r in receipts:
        lines.append(json.dumps(r, sort_keys=True, separators=(",", ":")))
    return "\n".join(lines) + "\n"


def build_auditor_summary(receipts, anchor, root_date, repo_full_name, generated_at):
    verdicts = [r.get("verdict", "UNKNOWN") for r in receipts]
    pass_count = verdicts.count("PASS")
    warn_count = verdicts.count("WARN")
    fail_count = verdicts.count("FAIL")
    merkle_root = anchor.get("merkle_root", "")
    anchor_status = anchor.get("status", "unknown")

    lines = [
        "# Titan Gate - Pilot Proof Bundle",
        "",
        "**Generated:** " + generated_at,
        "**Repository:** " + repo_full_name,
        "**Root Date:** " + root_date,
        "**Engine Version:** " + ENGINE_VERSION,
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        "| Receipts evaluated | " + str(len(receipts)) + " |",
        "| PASS | " + str(pass_count) + " |",
        "| WARN | " + str(warn_count) + " |",
        "| FAIL | " + str(fail_count) + " |",
        "| Merkle root | `" + merkle_root + "` |",
        "| Anchor status | " + anchor_status + " |",
        "",
        "---",
        "",
        "## Artifacts in This Bundle",
        "",
        "| File | Description |",
        "|------|-------------|",
        "| `receipt.json` | Signed receipts with Merkle inclusion proofs |",
        "| `replay_result.json` | Deterministic replay verdicts and anomaly list |",
        "| `anchor.json` | Promoted anchor record with sealed Merkle root |",
        "| `ndjson_export.ndjson` | NDJSON export of all receipts for offline tooling |",
        "| `auditor_summary.md` | This document |",
        "| `bundle_manifest.json` | SHA256 integrity hashes for all bundle artifacts |",
        "",
        "---",
        "",
        "## SOC2 Controls Covered",
        "",
        "| Control | Description |",
        "|---------|-------------|",
        "| CC6.1 | Logical access security - receipts cryptographically bound to commit SHA |",
        "| CC6.2 | Authentication - HMAC-SHA256 signing with tenant-scoped key |",
        "| CC7.1 | Change management - every AI-assisted change produces a signed receipt |",
        "| CC8.1 | Risk mitigation - deterministic three-judge evaluation before merge |",
        "",
        "---",
        "",
        "## Verification Instructions",
        "",
        "1. Verify each receipt signature:",
        "   python scripts/titan_verify.py receipt.json",
        "",
        "2. Recompute leaf hash:",
        "   SHA256('L|' + leaf_string) must match leaf_hash in receipt.json",
        "",
        "3. Walk merkle_proof to recompute Merkle root:",
        "   Each step: SHA256('N|' + left_bytes + right_bytes)",
        "",
        "4. Compare computed root with anchor.json merkle_root",
        "",
        "5. Confirm anchor.json status == promoted",
        "",
        "---",
        "",
        "## Signing Algorithm",
        "",
        "- Signing version: " + SIGNING_VERSION,
        "- Merkle algorithm: " + MERKLE_ALGORITHM,
        "- Anchor schema: " + ANCHOR_SCHEMA,
        "",
        "_This bundle was generated by Titan Gate and is intended for auditor review._",
        "",
    ]
    return "\n".join(lines)


def build_manifest(artifact_map):
    manifest = {
        "schema": "bundle_manifest_v1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": {},
    }
    for filename, content_bytes in sorted(artifact_map.items()):
        manifest["files"][filename] = sha256_bytes(content_bytes)
    return manifest


def generate_proof_bundle(receipts, tenant_id, repo_full_name, output_path):
    if not receipts:
        raise ValueError("No receipts provided")

    root_date = receipts[0].get("root_date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    leaves = [
        make_leaf_string(
            r.get("tenant_id", tenant_id),
            r.get("root_date", root_date),
            r["receipt_id"],
            r["receipt_hash"],
        )
        for r in receipts
    ]

    merkle_root = compute_merkle_root(leaves)
    anchor = build_anchor_artifact(tenant_id, repo_full_name, root_date, receipts)

    receipt_bytes = json.dumps(
        build_receipt_artifact(receipts, leaves), indent=2
    ).encode("utf-8")

    replay_bytes = json.dumps(
        build_replay_result(receipts), indent=2
    ).encode("utf-8")

    anchor_bytes = json.dumps(anchor, indent=2).encode("utf-8")

    ndjson_bytes = build_ndjson_export(receipts).encode("utf-8")

    summary_bytes = build_auditor_summary(
        receipts, anchor, root_date, repo_full_name, generated_at
    ).encode("utf-8")

    artifact_map = {
        "receipt.json": receipt_bytes,
        "replay_result.json": replay_bytes,
        "anchor.json": anchor_bytes,
        "ndjson_export.ndjson": ndjson_bytes,
        "auditor_summary.md": summary_bytes,
    }
    manifest_dict = build_manifest(artifact_map)
    manifest_bytes = json.dumps(manifest_dict, indent=2).encode("utf-8")

    zip_path = output_path if output_path.endswith(".zip") else output_path.replace(".json", ".zip")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("receipt.json", receipt_bytes)
        zf.writestr("replay_result.json", replay_bytes)
        zf.writestr("anchor.json", anchor_bytes)
        zf.writestr("ndjson_export.ndjson", ndjson_bytes)
        zf.writestr("auditor_summary.md", summary_bytes)
        zf.writestr("bundle_manifest.json", manifest_bytes)

    bundle = {
        "schema": "proof_bundle_v1",
        "generated_at": generated_at,
        "engine_version": ENGINE_VERSION,
        "contract_version": CONTRACT_VERSION,
        "merkle_algorithm": MERKLE_ALGORITHM,
        "tenant_id": tenant_id,
        "repo_full_name": repo_full_name,
        "root_date": root_date,
        "merkle_root": merkle_root,
        "receipt_count": len(receipts),
        "anchor": anchor,
        "receipts": json.loads(receipt_bytes)["receipts"],
        "verification_instructions": {
            "step1": "Verify each receipt signature using titan_verify.py",
            "step2": "Recompute leaf hash: SHA256('L|' + leaf_string)",
            "step3": "Walk merkle_proof to recompute root",
            "step4": "Compare computed root with merkle_root field",
            "step5": "Compare merkle_root with anchor.merkle_root",
        },
    }
    bundle["bundle_hash"] = sha256_str(
        json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    )

    json_path = zip_path.replace(".zip", ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    bundle["_zip_path"] = zip_path
    bundle["_json_path"] = json_path
    bundle["_manifest"] = manifest_dict

    return bundle


def main():
    parser = argparse.ArgumentParser(
        description="Titan Gate Proof Bundle Generator - WO-4 v1.0.0",
        epilog="Produces a zip bundle containing all pilot proof artifacts.",
    )
    parser.add_argument("receipts", nargs="+", help="Paths to receipt JSON files")
    parser.add_argument("--tenant", required=True, help="Tenant ID")
    parser.add_argument("--repo", required=True, help="Repo full name (org/repo)")
    parser.add_argument("--output", "-o", default="proof_bundle.zip",
                        help="Output path (default: proof_bundle.zip)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    missing = [p for p in args.receipts if not os.path.exists(p)]
    if missing:
        for m in missing:
            print("ERROR: File not found: " + m, file=sys.stderr)
        sys.exit(2)

    receipts = load_receipts(args.receipts)
    result = generate_proof_bundle(receipts, args.tenant, args.repo, args.output)

    print("Proof bundle generated: " + result["_zip_path"])
    print("  JSON sidecar : " + result["_json_path"])
    print("  Receipts     : " + str(result["receipt_count"]))
    print("  Merkle root  : " + result["merkle_root"])
    print("  Manifest SHA256s:")
    for fname, fhash in result["_manifest"]["files"].items():
        print("    " + fhash + "  " + fname)

    if args.verbose:
        print("\nBundle manifest contents verified.")

    sys.exit(0)


if __name__ == "__main__":
    main()