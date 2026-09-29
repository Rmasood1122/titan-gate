#!/usr/bin/env python3
"""
Titan Gate Receipt Verifier
TRS-1 (Titan Receipt Standard) v1.0.0 — plus ed25519-v1 signing (WO-1)
and chain-walk verification (WO-2)

HMAC path (signing_version: hmac-sha256-v1): Python standard library only,
zero dependencies, behavior byte-identical to titan-verify 1.0.0.
Ed25519 path (signing_version: ed25519-v1): requires the `cryptography`
package, imported lazily — installing nothing still gives a fully working
legacy verifier.

Usage:
    titan-verify <receipt.json> --key <hex_key>            # legacy TRS-1 / HMAC
    titan-verify <receipt.json> --pubkey <pubkey_file>     # ed25519-v1 (public key only)
    titan-verify --chain <dir|file.jsonl> [--key ...] [--pubkey ...]
        # chain-walk: claimed order = lexicographic *.json filenames (dir)
        # or line order (.jsonl). Receipt 0 must have prev_receipt_hash ==
        # "GENESIS"; every receipt[n].prev_receipt_hash must equal
        # receipt[n-1].receipt_hash; every receipt is also individually
        # verified (hash + signature, dispatched on its signing_version).
"""

import argparse
import hashlib
import hmac
import json
import os
import sys

__version__ = "1.2.0"
__spec__ = "TRS-1 v1.0.0 (+ ed25519-v1, chain-walk)"

# NOTE (WO-3): api/receipt_signing.py defines an identical EXCLUSION_FIELDS and
# canonical_bytes. Confirmed IDENTICAL as of the WO-1 patch (the divergence
# logged for WO-3 lived in a stale Mar-6 local copy, not in main). Two
# definitions is still one too many — unify into a single shared module in
# TRS-2 (WO-3). Do NOT edit one without the other.
try:
    from titan_gate.canonical import EXCLUSION_FIELDS, canonical_bytes  # noqa: F401
except ImportError:  # script mode: verify.py run directly, sibling import
    from canonical import EXCLUSION_FIELDS, canonical_bytes  # noqa: F401


REQUIRED_FIELDS = [
    "schema_version", "receipt_id", "tenant_id", "repo", "repo_full_name",
    "pr_number", "evaluated_at", "root_date", "engine_version",
    "contract_version", "scoring_formula_version", "policy_version",
    "merkle_algorithm", "signing_version", "structural_score",
    "semantic_score", "composite_score", "verdict",
    "hard_violations", "process_violations",
    "artifact_hash", "scope_hash", "provenance_hash",
    "prev_receipt_hash", "receipt_hash", "signature", "ai_attributed",
]




def verify_receipt(path, key_hex=None, fmt="text", quiet=False, pubkey_path=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            receipt = json.load(f)
    except FileNotFoundError:
        _output(fmt, ok=False, err_code="ERR_FILE_NOT_FOUND", message=f"File not found: {path}", quiet=quiet)
        return 2
    except json.JSONDecodeError as e:
        _output(fmt, ok=False, err_code="ERR_JSON_INVALID", message=f"Invalid JSON: {e}", quiet=quiet)
        return 2

    # Guarded, not moved: preserves the legacy error-precedence exactly when
    # --key is supplied (case check fires before required-field checks, as in
    # 1.0.0). Only skipped when no --key was given (pubkey-mode invocations).
    if key_hex is not None:
        key_hex = key_hex.strip()
        if key_hex != key_hex.lower():
            _output(fmt, ok=False, err_code="ERR_HEX_CASE_INVALID", message="Key must be lowercase hex", quiet=quiet)
            return 2

    for field in REQUIRED_FIELDS:
        if field not in receipt:
            _output(fmt, ok=False, err_code="ERR_SCHEMA_INVALID", message=f"Missing required field: {field}", quiet=quiet)
            return 1

    if receipt.get("schema_version") != "receipt_v1":
        _output(fmt, ok=False, err_code="ERR_SCHEMA_VERSION", message=f"Unsupported schema version", quiet=quiet)
        return 1

    signing_version = receipt.get("signing_version")
    if signing_version == "hmac-sha256-v1":
        return _verify_hmac(receipt, key_hex, fmt, quiet)
    if signing_version == "ed25519-v1":
        return _verify_ed25519(receipt, pubkey_path, fmt, quiet)
    _output(fmt, ok=False, err_code="ERR_SIGNING_VERSION_UNKNOWN", message=f"Unsupported signing version: {signing_version}", quiet=quiet)
    return 1


def _verify_hmac(receipt, key_hex, fmt, quiet):
    """Legacy TRS-1 verification. Body below is the 1.0.0 code moved verbatim;
    only the missing-key guard is new (previously argparse enforced --key)."""
    if key_hex is None:
        _output(fmt, ok=False, err_code="ERR_KEY_REQUIRED",
                message="hmac-sha256-v1 receipts require --key <hex_key>", quiet=quiet)
        return 2

    signing_version = receipt.get("signing_version")

    sig = receipt.get("signature", "")
    if len(sig) != 64:
        _output(fmt, ok=False, err_code="ERR_SIG_INVALID_LENGTH", message=f"Signature must be 64 hex chars, got {len(sig)}", quiet=quiet)
        return 1

    canon = canonical_bytes(receipt)
    computed_hash = hashlib.sha256(canon).hexdigest()
    stored_hash = receipt.get("receipt_hash", "")
    hash_valid = hmac.compare_digest(computed_hash, stored_hash)

    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        _output(fmt, ok=False, err_code="ERR_KEY_INVALID", message="Key is not valid hex", quiet=quiet)
        return 2

    expected_sig = hmac.new(key_bytes, canon, hashlib.sha256).hexdigest()
    sig_valid = hmac.compare_digest(expected_sig, sig)

    prev_hash = receipt.get("prev_receipt_hash", "")
    if prev_hash == "GENESIS":
        chain_status = "GENESIS"
    elif prev_hash and len(prev_hash) == 64:
        chain_status = "VALID"
    else:
        chain_status = "UNKNOWN"

    overall_valid = hash_valid and sig_valid

    receipt_id = receipt.get("receipt_id", "unknown")
    tenant = receipt.get("tenant_id", "unknown")
    repo = receipt.get("repo_full_name", receipt.get("repo", "unknown"))
    verdict = receipt.get("verdict", "unknown")
    score = receipt.get("composite_score", 0)
    evaluated_at = receipt.get("evaluated_at", "unknown")
    receipt_hash = receipt.get("receipt_hash", "unknown")

    if overall_valid:
        _output(fmt, ok=True, receipt_id=receipt_id, tenant=tenant, repo=repo,
                verdict=verdict, score=score, evaluated_at=evaluated_at,
                receipt_hash=receipt_hash, sig_valid=sig_valid, hash_valid=hash_valid,
                chain_status=chain_status, signing_version=signing_version,
                merkle_algorithm=receipt.get("merkle_algorithm", "merkle_v1"), quiet=quiet)
        return 0
    else:
        err_code = "ERR_SIG" if not sig_valid else "ERR_HASH"
        anomaly = "SIGNATURE_MISMATCH" if not sig_valid else "HASH_MISMATCH"
        _output(fmt, ok=False, err_code=err_code, message=f"ANOMALY: {anomaly}",
                receipt_id=receipt_id, tenant=tenant, repo=repo,
                verdict=verdict, score=score, evaluated_at=evaluated_at, quiet=quiet)
        return 1


def _verify_ed25519(receipt, pubkey_path, fmt, quiet):
    """ed25519-v1 verification with the PUBLIC key only (WO-1, kills G1:
    the auditor's verify input can no longer forge). `cryptography` is
    imported lazily so the HMAC path remains zero-dependency."""
    if pubkey_path is None:
        _output(fmt, ok=False, err_code="ERR_PUBKEY_REQUIRED",
                message="ed25519-v1 receipts require --pubkey <pubkey_file>", quiet=quiet)
        return 2

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        _output(fmt, ok=False, err_code="ERR_DEPENDENCY_MISSING",
                message="ed25519-v1 verification requires the 'cryptography' package: pip install cryptography",
                quiet=quiet)
        return 2

    try:
        with open(pubkey_path, "r", encoding="utf-8") as f:
            pub_hex = f.read().strip()
    except FileNotFoundError:
        _output(fmt, ok=False, err_code="ERR_PUBKEY_NOT_FOUND",
                message=f"Public key file not found: {pubkey_path}", quiet=quiet)
        return 2
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    except (ValueError, TypeError) as e:
        _output(fmt, ok=False, err_code="ERR_PUBKEY_INVALID",
                message=f"Public key file is not a valid 32-byte hex Ed25519 key: {e}", quiet=quiet)
        return 2

    signing_version = receipt.get("signing_version")

    sig_hex = receipt.get("signature", "")
    if len(sig_hex) != 128:
        _output(fmt, ok=False, err_code="ERR_SIG_INVALID_LENGTH",
                message=f"Ed25519 signature must be 128 hex chars, got {len(sig_hex)}", quiet=quiet)
        return 1
    try:
        signature = bytes.fromhex(sig_hex)
    except ValueError:
        _output(fmt, ok=False, err_code="ERR_SIG_INVALID",
                message="Signature is not valid hex", quiet=quiet)
        return 1

    # signing_version sits INSIDE the signed body (api/signers.py writes it
    # before signing), so a downgrade edit to the version field invalidates
    # the signature here as well — the CLI inherits the downgrade protection.
    canon = canonical_bytes(receipt)
    computed_hash = hashlib.sha256(canon).hexdigest()
    stored_hash = receipt.get("receipt_hash", "")
    hash_valid = hmac.compare_digest(computed_hash, stored_hash)

    try:
        pub.verify(signature, canon)
        sig_valid = True
    except InvalidSignature:
        sig_valid = False

    prev_hash = receipt.get("prev_receipt_hash", "")
    if prev_hash == "GENESIS":
        chain_status = "GENESIS"
    elif prev_hash and len(prev_hash) == 64:
        chain_status = "VALID"
    else:
        chain_status = "UNKNOWN"

    overall_valid = hash_valid and sig_valid

    receipt_id = receipt.get("receipt_id", "unknown")
    tenant = receipt.get("tenant_id", "unknown")
    repo = receipt.get("repo_full_name", receipt.get("repo", "unknown"))
    verdict = receipt.get("verdict", "unknown")
    score = receipt.get("composite_score", 0)
    evaluated_at = receipt.get("evaluated_at", "unknown")
    receipt_hash = receipt.get("receipt_hash", "unknown")

    if overall_valid:
        _output(fmt, ok=True, receipt_id=receipt_id, tenant=tenant, repo=repo,
                verdict=verdict, score=score, evaluated_at=evaluated_at,
                receipt_hash=receipt_hash, sig_valid=sig_valid, hash_valid=hash_valid,
                chain_status=chain_status, signing_version=signing_version,
                merkle_algorithm=receipt.get("merkle_algorithm", "merkle_v1"), quiet=quiet)
        return 0
    else:
        err_code = "ERR_SIG" if not sig_valid else "ERR_HASH"
        anomaly = "SIGNATURE_MISMATCH" if not sig_valid else "HASH_MISMATCH"
        _output(fmt, ok=False, err_code=err_code, message=f"ANOMALY: {anomaly}",
                receipt_id=receipt_id, tenant=tenant, repo=repo,
                verdict=verdict, score=score, evaluated_at=evaluated_at, quiet=quiet)
        return 1


# ---------------------------------------------------------------------------
# WO-2: chain-walk verification
# ---------------------------------------------------------------------------

def _check_receipt_silent(receipt, key_hex, ed25519_pub, invalid_signature_exc):
    """Per-receipt verification for chain mode: (ok, err_code, message), no
    printing. DELIBERATELY replicates (not refactors) the single-receipt
    logic above — the legacy functions are golden-pinned byte-identical and
    stay untouched. ed25519_pub is a pre-loaded Ed25519PublicKey or None."""
    for field in REQUIRED_FIELDS:
        if field not in receipt:
            return False, "ERR_SCHEMA_INVALID", f"Missing required field: {field}"
    if receipt.get("schema_version") != "receipt_v1":
        return False, "ERR_SCHEMA_VERSION", "Unsupported schema version"

    signing_version = receipt.get("signing_version")
    canon = canonical_bytes(receipt)
    computed_hash = hashlib.sha256(canon).hexdigest()
    hash_valid = hmac.compare_digest(computed_hash, receipt.get("receipt_hash", ""))

    if signing_version == "hmac-sha256-v1":
        if key_hex is None:
            return False, "ERR_KEY_REQUIRED", "hmac-sha256-v1 receipt requires --key"
        try:
            key_bytes = bytes.fromhex(key_hex)
        except ValueError:
            return False, "ERR_KEY_INVALID", "Key is not valid hex"
        expected_sig = hmac.new(key_bytes, canon, hashlib.sha256).hexdigest()
        sig_valid = hmac.compare_digest(expected_sig, receipt.get("signature", ""))
    elif signing_version == "ed25519-v1":
        if ed25519_pub is None:
            return False, "ERR_PUBKEY_REQUIRED", "ed25519-v1 receipt requires --pubkey"
        try:
            signature = bytes.fromhex(receipt.get("signature", ""))
            ed25519_pub.verify(signature, canon)
            sig_valid = True
        except (ValueError, invalid_signature_exc):
            sig_valid = False
    else:
        return False, "ERR_SIGNING_VERSION_UNKNOWN", f"Unsupported signing version: {signing_version}"

    if hash_valid and sig_valid:
        return True, None, None
    if not sig_valid:
        return False, "ERR_SIG", "ANOMALY: SIGNATURE_MISMATCH"
    return False, "ERR_HASH", "ANOMALY: HASH_MISMATCH"


def _load_chain(chain_path):
    """Returns list of (label, receipt) in claimed order.
    Directory: lexicographically sorted *.json filenames.
    File: JSONL, one receipt per line, line order."""
    if os.path.isdir(chain_path):
        entries = []
        for fn in sorted(f for f in os.listdir(chain_path) if f.endswith(".json")):
            with open(os.path.join(chain_path, fn), "r", encoding="utf-8") as f:
                entries.append((fn, json.load(f)))
        return entries
    entries = []
    with open(chain_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if line:
                entries.append((f"line {i + 1}", json.loads(line)))
    return entries


def _chain_output(fmt, ok, receipts_checked, err_code=None, break_position=None,
                  message=None, quiet=False):
    if fmt == "json":
        result = {
            "ok": ok, "result": "VALID" if ok else "INVALID",
            "receipts_checked": receipts_checked,
            "err_code": err_code, "break_position": break_position,
            "message": message,
        }
        if not quiet:
            print(json.dumps(result, indent=2))
        return
    if quiet and ok:
        return
    print("=" * 60)
    print("TITAN GATE CHAIN VERIFICATION")
    print("=" * 60)
    print(f"Receipts checked : {receipts_checked}")
    if ok:
        print("VERIFICATION     : PASS")
        print("Chain            : CONTINUOUS FROM GENESIS")
    else:
        print("VERIFICATION     : FAIL")
        if break_position is not None:
            print(f"Break position   : {break_position}")
        if message:
            print(f"  {message}")
    print("=" * 60)


def _verify_chain_trs2(entries, ed25519_pub, fmt, quiet,
                       profile="receipt_trs2_v1"):
    """WO-3.5b/WO-6: chain walk for TRS-2 chains, v1 and v2 (SPEC-2 s1.3:
    one profile per chain, selected at genesis).

    Per-receipt verification is DELEGATED to trs2_writer.verify_trs2_receipt
    (single implementation — duplicating the digest/signature rules here
    would recreate the divergence class WO-3.1 eliminated). This function
    owns only what a walk owns: prev-linkage, position naming, and
    per-receipt profile consistency. Import is lazy so HMAC-only TRS-1
    usage keeps zero dependencies."""
    if ed25519_pub is None:
        _chain_output(fmt, False, 0, "ERR_PUBKEY_REQUIRED", None,
                      f"{profile} chain requires --pubkey "
                      "(TRS-2 has no HMAC mode; no key can substitute)", quiet)
        return 2
    from titan_gate.trs2_writer import (
        verify_trs2_receipt, verify_trs2_receipt_v2, TRS2ReceiptError,
        TRS2_SCHEMA_VERSION_V2)
    # WO-6: one walk, version-dispatched per-receipt verifier. A second
    # copy of the walk would recreate the divergence class WO-3.1
    # eliminated (a future linkage fix landing in one copy only).
    verify_fn = (verify_trs2_receipt_v2
                 if profile == TRS2_SCHEMA_VERSION_V2
                 else verify_trs2_receipt)
    checked = 0
    prev_expected = None
    for idx, (label, receipt) in enumerate(entries):
        if receipt.get("schema_version") != profile:
            _chain_output(fmt, False, checked, "ERR_CHAIN_PROFILE_MISMATCH", idx,
                          f"Receipt at position {idx} ({label}) declares "
                          f"{receipt.get('schema_version')!r} in a "
                          f"{profile} chain — a chain has ONE "
                          f"profile, declared at genesis", quiet)
            return 1
        prev = receipt.get("prev_receipt_hash", "")
        if idx == 0:
            if prev != "GENESIS":
                _chain_output(fmt, False, checked, "ERR_CHAIN_GENESIS", 0,
                              f"Receipt at position 0 ({label}) has "
                              f"prev_receipt_hash != GENESIS", quiet)
                return 1
        elif prev != prev_expected:
            _chain_output(fmt, False, checked, "ERR_CHAIN_BROKEN", idx,
                          f"Chain broken at position {idx} ({label}): "
                          f"prev_receipt_hash does not match receipt_hash at "
                          f"position {idx - 1} — receipt missing, reordered, "
                          f"or altered", quiet)
            return 1
        try:
            verify_fn(receipt, ed25519_pub)
        except TRS2ReceiptError as e:
            _chain_output(fmt, False, checked, "ERR_RECEIPT_INVALID", idx,
                          f"Receipt at position {idx} ({label}): {e}", quiet)
            return 1
        prev_expected = receipt.get("receipt_hash", "")
        checked += 1
    _chain_output(fmt, True, checked, None, None, None, quiet)
    return 0


def _verify_chain(chain_path, key_hex, pubkey_path, fmt, quiet):
    if key_hex is not None:
        key_hex = key_hex.strip()
        if key_hex != key_hex.lower():
            _chain_output(fmt, False, 0, "ERR_HEX_CASE_INVALID", None,
                          "Key must be lowercase hex", quiet)
            return 2

    ed25519_pub = None
    invalid_signature_exc = ValueError  # placeholder; replaced when loaded
    if pubkey_path is not None:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except ImportError:
            _chain_output(fmt, False, 0, "ERR_DEPENDENCY_MISSING", None,
                          "ed25519-v1 verification requires the 'cryptography' package: pip install cryptography",
                          quiet)
            return 2
        try:
            with open(pubkey_path, "r", encoding="utf-8") as f:
                pub_hex = f.read().strip()
            ed25519_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
            invalid_signature_exc = InvalidSignature
        except FileNotFoundError:
            _chain_output(fmt, False, 0, "ERR_PUBKEY_NOT_FOUND", None,
                          f"Public key file not found: {pubkey_path}", quiet)
            return 2
        except (ValueError, TypeError) as e:
            _chain_output(fmt, False, 0, "ERR_PUBKEY_INVALID", None,
                          f"Public key file is not a valid 32-byte hex Ed25519 key: {e}", quiet)
            return 2

    try:
        entries = _load_chain(chain_path)
    except FileNotFoundError:
        _chain_output(fmt, False, 0, "ERR_CHAIN_PATH", None,
                      f"Chain path not found: {chain_path}", quiet)
        return 2
    except json.JSONDecodeError as e:
        _chain_output(fmt, False, 0, "ERR_JSON_INVALID", None,
                      f"Invalid JSON in chain input: {e}", quiet)
        return 2

    if not entries:
        _chain_output(fmt, False, 0, "ERR_CHAIN_EMPTY", None,
                      f"No receipts found at: {chain_path}", quiet)
        return 2

    genesis_profile = entries[0][1].get("schema_version", "receipt_v1")
    if genesis_profile in ("receipt_trs2_v1", "receipt_trs2_v2"):
        return _verify_chain_trs2(entries, ed25519_pub, fmt, quiet,
                                  profile=genesis_profile)
    if genesis_profile != "receipt_v1":
        _chain_output(fmt, False, 0, "ERR_SCHEMA_VERSION", 0,
                      f"Unknown schema_version at genesis: {genesis_profile!r} "
                      f"— no canonicalization fallback exists by design", quiet)
        return 1

    checked = 0
    prev_expected = None
    for idx, (label, receipt) in enumerate(entries):
        prev = receipt.get("prev_receipt_hash", "")
        if idx == 0:
            if prev != "GENESIS":
                _chain_output(fmt, False, checked, "ERR_CHAIN_GENESIS", 0,
                              f"Receipt at position 0 ({label}) has prev_receipt_hash != GENESIS — "
                              f"chain does not start at genesis (missing head?)", quiet)
                return 1
        else:
            if prev != prev_expected:
                _chain_output(fmt, False, checked, "ERR_CHAIN_BROKEN", idx,
                              f"Chain broken at position {idx} ({label}): prev_receipt_hash does not "
                              f"match receipt_hash at position {idx - 1} — receipt missing, reordered, "
                              f"or altered", quiet)
                return 1

        ok, err_code, msg = _check_receipt_silent(receipt, key_hex, ed25519_pub, invalid_signature_exc)
        if not ok:
            _chain_output(fmt, False, checked, err_code, idx,
                          f"Receipt at position {idx} ({label}): {msg}", quiet)
            return 1

        prev_expected = receipt.get("receipt_hash", "")
        checked += 1

    _chain_output(fmt, True, checked, None, None, None, quiet)
    return 0


def _output(fmt, ok, err_code=None, message=None, receipt_id=None,
            tenant=None, repo=None, verdict=None, score=None,
            evaluated_at=None, receipt_hash=None, sig_valid=None,
            hash_valid=None, chain_status=None, signing_version=None,
            merkle_algorithm=None, quiet=False):

    if fmt == "json":
        result = {
            "ok": ok, "result": "VALID" if ok else "INVALID",
            "err_code": err_code, "message": message,
            "receipt_id": receipt_id, "receipt_hash": receipt_hash,
            "signature_valid": sig_valid, "receipt_hash_valid": hash_valid,
            "chain_status": chain_status, "signing_version": signing_version,
            "merkle_algorithm": merkle_algorithm, "verdict": verdict,
        }
        if not quiet:
            print(json.dumps(result, indent=2))
        return

    if quiet and ok:
        return

    print("=" * 60)
    print("TITAN GATE RECEIPT VERIFICATION")
    print("=" * 60)
    if receipt_id:
        print(f"Receipt ID   : {receipt_id}")
    if tenant:
        print(f"Tenant       : {tenant}")
    if repo:
        print(f"Repo         : {repo}")
    if verdict:
        print(f"Verdict      : {verdict}")
    if score is not None:
        print(f"Score        : {score}")
    if evaluated_at:
        print(f"Evaluated At : {evaluated_at}")
    print("-" * 60)
    if ok:
        print(f"VERIFICATION  : PASS")
        print(f"Signature     : VALID")
        print(f"Hash          : VALID")
        if chain_status:
            print(f"Chain         : {chain_status}")
    else:
        print(f"VERIFICATION  : FAIL")
        if message:
            print(f"  {message}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        prog="titan-verify",
        description="Titan Gate Receipt Verifier — TRS-1 v1.0.0 (+ ed25519-v1, chain-walk)",
    )
    parser.add_argument("receipt", nargs="?", help="Path to receipt JSON file (single-receipt mode)")
    parser.add_argument("--chain", help="Path to a chain: directory of *.json receipts (lexicographic order) or a .jsonl file (line order)")
    parser.add_argument("--key", help="Hex-encoded HMAC signing key (hmac-sha256-v1 receipts)")
    parser.add_argument("--pubkey", help="Path to Ed25519 public key file, 32-byte hex (ed25519-v1 receipts)")
    parser.add_argument("--format", default="text", choices=["text", "json"])
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args()

    if args.version:
        print(f"titan-verify {__version__} ({__spec__})")
        sys.exit(0)

    if args.chain:
        sys.exit(_verify_chain(chain_path=args.chain, key_hex=args.key,
                               pubkey_path=args.pubkey, fmt=args.format,
                               quiet=args.quiet))

    if args.receipt is None:
        parser.error("a receipt path is required (or use --chain <dir|file.jsonl>)")

    sys.exit(verify_receipt(path=args.receipt, key_hex=args.key, fmt=args.format,
                            quiet=args.quiet, pubkey_path=args.pubkey))


if __name__ == "__main__":
    main()
