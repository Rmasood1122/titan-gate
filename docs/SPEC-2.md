Titan Receipt Standard — TRS-2
Agent-Action Receipt Profile & Verification Specification v2.0.0-draft
Status: Draft (normative text stabilizes at first external verification)
Author: Rehan Masood
Repository: https://github.com/Rehanrana11/titan-gate
License: CC BY 4.0

Abstract

TRS-2 extends the Titan Receipt Standard from AI-assisted code changes
(TRS-1) to AI agent actions. A TRS-2 receipt is a signed, chained record
of one agent action ingested from a customer's existing agent or
enforcement stack: what acted, on whose behalf, what it did (by hash
reference, never content), and what outcome the source recorded.
Receipts are independently verifiable offline with only the public
verifier, the receipt set, and the tenant's public key.

This document also records the relationship to TRS-1 v1.0.0 (frozen)
and the post-publication verifier extensions, and maps TRS-2 to CSA
AARM requirements R5 and R6 with an implementation-status column.

1. Relationship to TRS-1

1.1 TRS-1 v1.0.0 (docs/SPEC.md, published 2026-03-06) is FROZEN. Its
    normative text, field set, sorted-keys canonicalization, and
    hmac-sha256-v1 signing profile are unchanged and remain valid for
    receipts declaring schema_version "receipt_v1". Golden test vectors
    pin its byte-level behavior; conforming implementations MUST NOT
    alter TRS-1 processing.

1.2 Post-publication verifier extensions (recorded here, not by
    amending v1.0.0):
    - signing_version "ed25519-v1" (verifier v1.1.0, 2026-08): Ed25519
      signatures verified with a public key only, via
      `titan-verify --pubkey`. The hmac-sha256-v1 legacy path remains
      supported and golden-pinned. Under hmac-sha256-v1, possession of
      the verification key implies the ability to forge; ed25519-v1
      removes this property and is REQUIRED for any receipt presented
      to a third-party verifier.
    - Chain-walk verification (verifier v1.2.0, 2026-08):
      `titan-verify --chain` walks a receipt chain from GENESIS and
      detects deletion, reordering, forking, and body tampering,
      reporting the 0-based position of the first break.

1.3 Canonicalization is profile-bound. TRS-1 uses sorted-keys JSON and
    admits floating-point score fields; TRS-2 uses RFC 8785 (JCS) and
    admits no non-integer numbers (§3). TRS-1 receipts MUST NOT be
    canonicalized under JCS and TRS-2 receipts MUST NOT be
    canonicalized under the TRS-1 rules. A receipt's schema_version
    selects its canonicalization; there is no negotiation.

2. TRS-2 Event Profile (normative)

2.1 An event is a JSON object with EXACTLY these top-level fields:

    source_id        string, non-empty  Ingest source identifier
    source_event_id  string, non-empty  Source-native event ID
                                        (idempotency key with source_id)
    event_time       string, non-empty  Source-claimed time, ISO 8601 UTC
    ingest_time      string, non-empty  Ingest time, ISO 8601 UTC
    agent_ref        string, non-empty  Acting agent reference
    principal_ref    string, non-empty  Initiating principal reference
    action           object             §2.2
    outcome          object             §2.3

2.2 action contains EXACTLY: category (string), operation (string),
    target_hash (digest, §2.5), attributes_hash (digest, §2.5).
    Action content NEVER appears; only its digests. Hashing occurs
    at the ingestion edge, before schema validation.

2.3 outcome contains EXACTLY: value (string, non-empty) and
    recorded_by_source, a STRUCTURAL CONSTANT true. Outcomes enter the
    system only from source telemetry. A serializer or validator
    encountering any value other than the literal boolean true MUST
    reject the event as a schema error; the field is not caller-settable.
    Rationale: the evidence plane records what the customer's stack
    stated; it never originates outcomes (the enforcer cannot be the
    notary — and neither can we).

2.4 The field sets in §2.1–2.3 are CLOSED at every level. Unknown
    fields MUST be rejected, not ignored: a payload-bearing field
    cannot exist in a conforming receipt because there is no field to
    fill and no field may be added.

2.5 Digest fields are SHA-256 rendered as exactly 64 LOWERCASE hex
    characters. Validators MUST match the full string (no trailing
    bytes, no uppercase, no whitespace). Two renderings of one digest
    are not permitted to exist.

2.6 Ordering. Chain position (seq) is assigned strictly by arrival.
    event_time is recorded for display and analysis and NEVER
    determines chain position. Rationale (normative): ordering by
    source-claimed time would let a late-arriving, backdated event
    insert before existing receipts — an alteration channel inside the
    spec itself. Out-of-order event_time is expected; timelines render
    it with an ingested-late indication, chains prove arrival order.

3. Canonicalization (normative)

3.1 TRS-2 canonical bytes are produced per RFC 8785 (JCS) with one
    domain restriction: TRS-2 admits NO non-integer numbers, and
    integers MUST lie within ±(2^53 − 1). Serializers MUST reject
    values outside this domain — including negative zero and any
    IEEE-754 special value — never coerce or normalize them.

3.2 Within the admitted domain, output is byte-identical to full
    RFC 8785, including: UTF-8 encoding, no insignificant whitespace,
    the §3.2.2.2 escape rules (two-character shorthands; \u00xx for
    other controls below U+0020; all other characters literal), and
    object keys sorted by UTF-16 CODE UNITS. Implementations in
    languages whose native string ordering is by Unicode codepoint
    (e.g. Python) MUST NOT use native sort for keys: the orders
    diverge for non-BMP characters.

3.3 Rationale for the domain restriction: ECMAScript number
    serialization (RFC 8785 §3.2.2.3) is not byte-reproducible from
    all environments; excluding non-integers from the value domain
    removes the divergence class instead of approximating it. This is
    also why TRS-1, whose schema contains score floats, is permanently
    excluded from JCS (§1.3).

4. Chaining, signing, verification

4.1 TRS-2 receipts chain and sign per the TRS-1 mechanism as extended
    in §1.2: prev_receipt_hash links receipts, GENESIS opens a chain,
    ed25519-v1 signs canonical bytes, and the offline verifier detects
    deletion, reordering, forking, and alteration with position.

4.2 Verification requires only: the receipt set, the tenant public
    key, and the published verifier. No network, no vendor systems.

5. CSA AARM R5/R6 Mapping

Status column (claims discipline): IMPLEMENTED = an executable
acceptance test passes in the public repository as of this document's
date. SPECIFIED = normative here, acceptance test not yet passing.
No row overstates.

  AARM requirement            TRS-2 mechanism                Status
  ------------------------------------------------------------------
  R5 Tamper-evident receipt   Signed (ed25519-v1), hash-     IMPLEMENTED
  generation: cryptographic   chained receipts; offline      (verifier +
  receipts binding action     verifier detects deletion/     CI writer)
  and integrity               reorder/fork/alteration with
                              position; closed no-payload
                              schema; JCS canonical bytes

  R5 (cont.) receipts for     Production writers emit TRS-2  SPECIFIED
  agent actions end-to-end    receipts from ingested agent
  in production ingest        events (Copilot export path)

  R5 (cont.) binding of       outcome.value recorded from    IMPLEMENTED
  outcome, attributed         source telemetry only;         (schema);
  to its origin               recorded_by_source structural  SPECIFIED
                              constant (§2.3)                (live ingest)

  R6 Identity binding:        agent_ref + principal_ref      SPECIFIED
  action → agent identity →   required, non-empty; missing   (fields
  initiating principal        lineage is never guessed       normative;
                                                             resolver
                                                             not built)

  Independent verification    Offline public-key verifier;   IMPLEMENTED
  (supports R5 evidential     no vendor dependency
  value)

  Customer-held signing keys  Signing service in customer    SPECIFIED
  (neutrality property)       trust domain                   (WO in
                                                             progress)

  External anchoring          Transparency log + qualified   SPECIFIED
  (Rekor + eIDAS QTS)         timestamp per anchor interval  (not built)

6. Conformance

An implementation conforms to the TRS-2 event profile if it accepts
every event valid under §2–§3 and rejects every event invalid under
them, byte-for-byte agreeing with the published test vectors. The
acceptance tests in the repository (tests/test_wo34_trs2_profile.py,
tests/test_wo34_jcs_canonical.py) are the executable form of this
section.

License: CC BY 4.0
