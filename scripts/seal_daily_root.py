#!/usr/bin/env python3
import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.anchor import build_anchor, compute_anchor_payload_hash
from api.merkle import compute_merkle_root, make_leaf_string
from api.constants import ENGINE_VERSION


def load_receipts_for_date(receipts_dir, tenant_id, root_date):
    receipts = []
    if not os.path.exists(receipts_dir):
        return receipts
    for fname in sorted(os.listdir(receipts_dir)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(receipts_dir, fname)
        try:
            with open(path) as f:
                r = json.load(f)
            if (r.get("tenant_id") == tenant_id and
                    r.get("root_date") == root_date):
                receipts.append(r)
        except Exception:
            continue
    return receipts


def get_anchor_path(base_dir, tenant_id, repo_name, root_date):
    return os.path.join(
        base_dir, ".titan-gate", "anchors",
        tenant_id, repo_name, f"{root_date}.json"
    )


def seal_daily_root(tenant_id, repo_full_name, root_date, receipts, base_dir):
    repo_name = repo_full_name.replace("/", "_")
    anchor_path = get_anchor_path(base_dir, tenant_id, repo_name, root_date)

    if os.path.exists(anchor_path):
        existing = json.load(open(anchor_path))
        if existing.get("status") == "promoted":
            print(f"SEALED: anchor already promoted for {root_date}")
            return existing, False

    os.makedirs(os.path.dirname(anchor_path), exist_ok=True)

    sealed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    anchor = build_anchor(tenant_id, repo_full_name, root_date, receipts)
    anchor["sealed_at"] = sealed_at
    anchor["status"] = "promoted"
    anchor["promoted_at"] = sealed_at
    anchor["engine_version"] = ENGINE_VERSION
    anchor["payload_hash"] = compute_anchor_payload_hash(anchor)

    with open(anchor_path, "w") as f:
        json.dump(anchor, f, indent=2)

    return anchor, True


def main():
    parser = argparse.ArgumentParser(
        description="Titan Gate Daily Merkle Root Sealer"
    )
    parser.add_argument("--tenant", required=True, help="Tenant ID")
    parser.add_argument("--repo", required=True, help="Repo full name (org/repo)")
    parser.add_argument("--date", help="Date to seal (YYYY-MM-DD, default: today)")
    parser.add_argument("--receipts-dir", default="receipts",
                        help="Directory containing receipt JSON files")
    parser.add_argument("--dir", default=".", help="Project root directory")
    parser.add_argument("--receipt-files", nargs="*",
                        help="Explicit receipt files to include")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--promote", action="store_true",
                        help="After sealing, promote the anchor to Rekor")
    parser.add_argument("--anchor-key", default=None,
                        help="Path to writer-side EC P-256 private key PEM "
                             "(anchoring key — NOT the tenant receipt key; "
                             "WO-7 eviction ledger)")
    parser.add_argument("--rekor-url", default="https://rekor.sigstore.dev",
                        help="Rekor base URL")
    args = parser.parse_args()

    root_date = args.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if args.receipt_files:
        receipts = []
        for path in args.receipt_files:
            with open(path) as f:
                receipts.append(json.load(f))
    else:
        receipts = load_receipts_for_date(
            args.receipts_dir, args.tenant, root_date
        )

    if not receipts:
        print(f"WARNING: No receipts found for {args.tenant} on {root_date}")
        print("Sealing empty anchor.")

    anchor, is_new = seal_daily_root(
        args.tenant, args.repo, root_date, receipts, args.dir
    )

    if is_new:
        print(f"SEALED: {root_date}")
        print(f"  Tenant       : {anchor['tenant_id']}")
        print(f"  Repo         : {anchor['repo_full_name']}")
        print(f"  Receipts     : {anchor['receipt_count']}")
        print(f"  Merkle Root  : {anchor['merkle_root']}")
        print(f"  Payload Hash : {anchor['payload_hash']}")
        print(f"  Sealed At    : {anchor['sealed_at']}")
        repo_name = args.repo.replace("/", "_")
        path = get_anchor_path(args.dir, args.tenant, repo_name, root_date)
        print(f"  Anchor Path  : {path}")
    else:
        print(f"SKIPPED: already sealed")

    if args.verbose and receipts:
        print(f"\nReceipts included ({len(receipts)}):")
        for r in receipts:
            print(f"  [{r.get('verdict')}] {r.get('receipt_id')} score={r.get('composite_score')}")

    if args.promote:
        if not args.anchor_key:
            print("ERROR: --promote requires --anchor-key (no key defaults, "
                  "ever — absent key = refuse to sign)")
            sys.exit(2)
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        with open(args.anchor_key, "rb") as f:
            _priv = serialization.load_pem_private_key(f.read(), password=None)
        _pub_pem = _priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")

        def _sign_fn(digest: bytes) -> bytes:
            # PREHASHED: digest IS the hash; plain ECDSA(SHA256) would
            # double-hash and Rekor rejects (wire-proven 2026-08-07)
            return _priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

        repo_name = args.repo.replace("/", "_")
        apath = get_anchor_path(args.dir, args.tenant, repo_name, root_date)
        status = promote_anchor(anchor_path=apath, sign_fn=_sign_fn,
                                public_key_pem=_pub_pem,
                                base_url=args.rekor_url)
        if status.ok:
            print(f"PROMOTED: root {status.root_hash[:16]}... anchored in Rekor")
            print(f"  Record: {status.record_path}")
        else:
            print(f"PROMOTION FAILED (sealed anyway, disclosed): {status.error[:120]}")
            print(f"  Disclosure: anchor_failure recorded in {apath}")
    sys.exit(0)

# ---------------------------------------------------------------------------
# WO-4.3 part 2b: promote a sealed anchor to Rekor
#
# Promotion is writer-layer POLICY (composition of the local anchor
# file with the Rekor mechanism); titan_gate/anchor_writer.py stays
# the reusable mechanism. The sign_fn here wraps a writer-side
# asymmetric ANCHORING key (--anchor-key), deliberately NOT the tenant
# receipt key: putting tenant-key material in the CI writer before the
# WO-7 customer container exists is the Rule-1 defect class. The
# anchoring key is on the WO-7 eviction ledger.
#
# State machine on the anchor file (in place, payload_hash recomputed
# after every mutation — a stale payload_hash is silent corruption):
#   pending --success--> anchored (+anchored_at, +rekor_record_path)
#   pending --external failure--> pending (+anchor_failure)   [no raise]
#   anchored --promote again--> no-op, no resubmission (idempotent:
#     a re-promotion that resubmits would duplicate PUBLIC log entries)
#   caller bug (missing/malformed file) --> RAISE, never disclose
# ---------------------------------------------------------------------------
import time as _time

from api.anchor import compute_anchor_payload_hash as _recompute_payload_hash
from titan_gate.anchor_writer import anchor_root as _anchor_root
from titan_gate.anchor_writer import AnchorWriteStatus as _AnchorWriteStatus


class PromoteAnchorError(ValueError):
    """Caller-side error: anchor file missing or malformed."""


def _save_anchor(anchor_path, anchor):
    anchor.pop("payload_hash", None)
    anchor["payload_hash"] = _recompute_payload_hash(anchor)
    tmp = anchor_path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(anchor, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, anchor_path)


def promote_anchor(*, anchor_path, sign_fn, public_key_pem, base_url,
                   timeout=30.0):
    """Promote one sealed anchor_v1 file to Rekor. Returns
    AnchorWriteStatus; raises PromoteAnchorError only on caller bugs."""
    try:
        with open(anchor_path, encoding="utf-8") as f:
            anchor = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise PromoteAnchorError(f"anchor file unreadable: {e}") from e
    if anchor.get("schema") != "anchor_v1":
        raise PromoteAnchorError(
            f"not an anchor_v1 file: schema={anchor.get('schema')!r}")
    root = anchor.get("merkle_root")
    if not isinstance(root, str) or len(root) != 64:
        raise PromoteAnchorError(f"anchor has no valid merkle_root: {root!r}")

    if anchor.get("status") == "anchored":
        return _AnchorWriteStatus(
            ok=True, root_hash=root,
            record_path=anchor.get("rekor_record_path", ""))

    out_dir = os.path.dirname(os.path.abspath(anchor_path))
    status = _anchor_root(root_hash_hex=root, sign_fn=sign_fn,
                          public_key_pem=public_key_pem,
                          base_url=base_url, out_dir=out_dir,
                          timeout=timeout)
    if status.ok:
        anchor["status"] = "anchored"
        anchor["anchored_at"] = int(_time.time())
        anchor["rekor_record_path"] = status.record_path
        anchor.pop("anchor_failure", None)
    else:
        anchor["anchor_failure"] = {
            "error": status.error, "timestamp": int(_time.time())}
    _save_anchor(anchor_path, anchor)
    return status


if __name__ == "__main__":
    main()
