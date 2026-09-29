Titan Receipt Standard — TRS-1
Public Verification Specification v1.0.0
Status: Stable
Published: 2026-03-06
Author: Rehan Masood
Repository: https://github.com/Rehanrana11/titan-gate
License: CC BY 4.0

Abstract
TRS-1 (Titan Receipt Standard) defines a cryptographic receipt format for AI-assisted code changes. Every code change evaluated under TRS-1 produces a receipt — a signed, chained, Merkle-anchored artifact that provides tamper-evident proof of what was evaluated, what verdict was reached, and that the record has not been altered.
TRS-1 receipts are independently verifiable by any party with access to the receipt file and the verification key. No network access, no database, no trusted third party is required for verification.

1. Design Goals

Independent verifiability — Any engineer can verify a receipt with a single command and no external dependencies.
Tamper evidence — Any modification to a receipt invalidates its cryptographic signature.
Chain integrity — Receipts form an append-only chain. Gaps or reordering are detectable.
Deterministic replay — Verification produces identical results on any machine at any time.
Compliance evidence — Receipts embed SOC2 Trust Services Criteria control mappings.
Zero trust — Verification requires no trust in the issuing system.


2. Terminology

Receipt — A signed JSON artifact produced by evaluating a code change.
Receipt chain — An ordered sequence of receipts linked by prev_receipt_hash.
Merkle ledger — A daily Merkle tree whose leaves are receipt hashes.
Anchor — A file storing a sealed daily Merkle root, stored in the repository.
Tenant — An isolated namespace for receipts. Identified by tenant_id.
GENESIS — The literal string used as prev_receipt_hash for the first receipt in a chain.


3. Receipt Format
Receipts are UTF-8 encoded JSON objects conforming to schema version receipt_v1.
3.1 Required Fields
FieldTypeDescriptionschema_versionstringMust be "receipt_v1"receipt_idstring (UUID v4)Globally unique receipt identifiertenant_idstringTenant namespace identifierrepostringRepository namerepo_full_namestringFull name: owner/repopr_numberintegerPull request numberpr_titlestringPull request title at evaluation timebranchstringSource branchbase_branchstringTarget branchcommit_shastring40-char lowercase hex Git commit SHAevaluated_atstringISO 8601 UTC: YYYY-MM-DDTHH:MM:SSZroot_datestringCalendar date UTC: YYYY-MM-DDengine_versionstringEvaluation engine versioncontract_versionstringAPI contract versionscoring_formula_versionstringScoring formula versionpolicy_versionstringPolicy pack versionmerkle_algorithmstringMust be "merkle_v1"signing_versionstringMust be "hmac-sha256-v1"structural_scorenumber [0.0–1.0]Structural evaluation scoresemantic_scorenumber [0.0–1.0]Semantic evaluation scorecomposite_scorenumber [0.0–1.0]Weighted composite scoreverdictstringPASS, WARN, or FAILhard_violationsarrayBlocking violations (H1–H10)process_violationsarrayWarning violations (P1–P6)artifact_hashstring (64 hex)SHA256 of evaluated artifact bytesscope_hashstring (64 hex)SHA256 of evaluated file scopeprovenance_hashstring (64 hex)SHA256 of composite provenanceprev_receipt_hashstringSHA256 of prior receipt, or "GENESIS"receipt_hashstring (64 hex)SHA256 of canonical receipt bytessignaturestring (64 hex)HMAC-SHA256 signatureai_attributedbooleanTrue if AI authorship detectedevaluation_manifestobjectVersion lock snapshot
3.2 Verdict Thresholds
PASS  >= 0.70 composite_score  AND  no hard violations
WARN  >= 0.40 composite_score  AND  no hard violations
FAIL   < 0.40 composite_score  OR   any hard violation present

4. Canonical JSON Serialization
The canonical form is used for both receipt_hash computation and HMAC signature computation.
Rules:

All fields are included except the following exclusion fields: signature, prev_receipt_hash_verified, _debug, _meta
Keys are sorted lexicographically (ascending)
No whitespace between tokens
UTF-8 encoding
All hex values must be lowercase

Python reference implementation:
pythonimport hashlib, hmac, json

EXCLUSION_FIELDS = {"signature", "prev_receipt_hash_verified", "_debug", "_meta"}

def canonical_bytes(receipt: dict) -> bytes:
    filtered = {k: v for k, v in receipt.items() if k not in EXCLUSION_FIELDS}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

5. Receipt Hash Computation
receipt_hash = SHA256(canonical_bytes(receipt))
The receipt_hash field is included in the canonical bytes used for signature computation.

6. Signature Computation
Algorithm: HMAC-SHA256
Signing version identifier: hmac-sha256-v1
Key format: Even-length lowercase hexadecimal string
Output format: 64-character lowercase hexadecimal string
signature = HMAC-SHA256(key, canonical_bytes(receipt))
The signature is computed over the canonical bytes of the receipt with exclusion fields removed. The receipt_hash field is present in the signed bytes.
Python reference implementation:
pythondef sign_receipt(receipt: dict, key_hex: str) -> str:
    key_bytes = bytes.fromhex(key_hex)
    canon = canonical_bytes(receipt)
    return hmac.new(key_bytes, canon, hashlib.sha256).hexdigest()

7. Chain Integrity
Each receipt includes prev_receipt_hash linking it to the previous receipt:

The first receipt in a chain sets prev_receipt_hash = "GENESIS"
Each subsequent receipt sets prev_receipt_hash to the receipt_hash of the immediately prior receipt
Receipts are ordered by evaluated_at (lexicographic ascending, which equals chronological ascending)
A broken chain link is a ERR_CHAIN anomaly

Chain verification algorithm:

Sort receipts by evaluated_at ascending
Verify first receipt has prev_receipt_hash == "GENESIS"
For each subsequent receipt N: verify receipt[N].prev_receipt_hash == receipt[N-1].receipt_hash


8. Merkle Ledger
Algorithm identifier: merkle_v1
Scope: One tree per tenant_id per root_date
8.1 Leaf Hash
leaf_hash = SHA256("L|" + leaf_data)
Where leaf_data is the canonical leaf string:
v1|{tenant_id}|{root_date}|{receipt_id}|{receipt_hash}
8.2 Node Hash
node_hash = SHA256("N|" + left_hash + right_hash)
Where left_hash and right_hash are 32-byte raw binary values (not hex strings).
8.3 Empty Tree
EMPTY_HASH = SHA256("TITAN_GATE_EMPTY_MERKLE_TREE_V1")
8.4 Tree Construction

Compute leaf hashes for all receipts in scope, sorted by receipt_id ascending
If leaf count is odd, duplicate the last leaf
Combine pairs into parent nodes up the tree
The root is the final single hash value

8.5 Root Sealing
Daily Merkle roots are sealed once per root_date. A sealed root is immutable. Any change to a sealed root is a CRITICAL_LEDGER_ANOMALY.

9. Anchor Files
Anchors store sealed daily Merkle roots in the repository.
Path: .titan-gate/anchors/{tenant_id}/{repo_name}/{date}.json
Schema:
json{
  "schema": "anchor_v1",
  "tenant_id": "string",
  "repo": "string",
  "root_date": "YYYY-MM-DD",
  "merkle_root": "64-hex-chars",
  "receipt_count": 0,
  "status": "promoted",
  "sealed_at": "YYYY-MM-DDTHH:MM:SSZ"
}
Lifecycle: pending → promoted. Anchors are never overwritten.

10. Verification Algorithm
A conformant verifier MUST execute these steps in order:

Parse — Load and parse the receipt JSON file
Schema validation — Verify schema_version == "receipt_v1" and all required fields present
Signing version check — Verify signing_version is a known value
Signature length check — For hmac-sha256-v1: signature must be exactly 64 hex characters
Receipt hash recomputation — Compute SHA256(canonical_bytes(receipt)) and compare to receipt_hash
Signature verification — Compute HMAC-SHA256(key, canonical_bytes(receipt)) and compare to signature using constant-time comparison
Chain link check — Verify prev_receipt_hash format (64 hex or "GENESIS")

All comparisons MUST use constant-time equality to prevent timing attacks.
10.1 Exit Codes
CodeMeaning0Verification PASS1Verification FAIL (cryptographic mismatch)2Invalid input (file not found, bad key format)
10.2 Error Codes
Error CodeMeaningERR_FILE_NOT_FOUNDReceipt file does not existERR_JSON_INVALIDReceipt is not valid JSONERR_SCHEMA_INVALIDRequired field missingERR_SCHEMA_VERSIONUnknown schema versionERR_SIGNING_VERSION_UNKNOWNUnknown signing versionERR_SIG_INVALID_LENGTHSignature wrong lengthERR_HEX_CASE_INVALIDHex values must be lowercaseERR_SIGSignature mismatchERR_HASHReceipt hash mismatchERR_CHAINChain link broken

11. Reference Verifier
The reference verifier is published as a zero-dependency Python package:
pip install titan-gate
titan-verify receipt.json --key <hex_key>
Source: https://github.com/Rehanrana11/titan-gate
PyPI: https://pypi.org/project/titan-gate/
Expected output on valid receipt:
============================================================
TITAN GATE RECEIPT VERIFICATION
============================================================
Receipt ID   : 89bd57ed-b7e1-455a-9f63-5d0005d8d27f
Tenant       : Rehanrana11
Repo         : Rehanrana11/titan-gate
Verdict      : PASS
Score        : 0.88
Evaluated At : 2026-03-06T12:31:45Z
------------------------------------------------------------
VERIFICATION  : PASS
Signature     : VALID
Hash          : VALID
Chain         : VALID
============================================================

12. SOC2 Control Mappings
TRS-1 receipts embed SOC2 Trust Services Criteria control mappings:
ControlDescriptionReceipt EvidenceCC6.1Logical access controlstenant_id isolation, API key as SHA256CC6.7Transmission integrityHMAC-SHA256 signature over canonical bytesCC7.2Monitoring for anomaliesReplay engine, chain integrity verificationCC8.1Change managementSigned receipt per PR, verdict + score recorded

13. Version History
VersionDateChanges1.0.02026-03-06Initial stable release

14. Implementation Notes

All hex values (hashes, signatures) MUST be lowercase
evaluated_at MUST be UTC with second precision: YYYY-MM-DDTHH:MM:SSZ
The receipt_hash field is included in signature computation
Merkle node hashing uses raw binary concatenation, not hex string concatenation
HMAC comparison MUST use constant-time equality (hmac.compare_digest in Python)


TRS-1 v1.0.0 — Titan Receipt Standard
Author: Rehan Masood — https://github.com/Rehanrana11/titan-gate
License: CC BY 4.0