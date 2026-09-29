# Security Policy

## What this project is

Titan Gate produces cryptographically verifiable receipts for AI agent
actions. Its security posture is fail-closed by design: verification
failures are always hard failures with position, never warnings; absent
or wrong keys refuse to sign or verify rather than degrade.

## Reporting a vulnerability

Report privately via GitHub Security Advisories on this repository
(Security tab → Report a vulnerability). Please do not open public
issues for suspected vulnerabilities.

You can expect an acknowledgment within 72 hours. Confirmed findings
are fixed with a regression test pinning the attack (see probe_24.py
for the standing adversarial battery — this project red-teams itself
and keeps the findings in public history).

## Supported versions

The `main` branch and the latest tagged release. TRS-1 receipt vectors
are golden-pinned: legacy receipts remain verifiable byte-identically,
and old verifiers refuse newer formats rather than silently accepting
them.

## Scope notes for researchers

Of particular interest: anything that lets a chain verify after
deletion, reordering, or alteration; any path by which vendor-domain
code could sign; canonicalization divergence between writer and
verifier; verification that passes against a wrong trust root.
