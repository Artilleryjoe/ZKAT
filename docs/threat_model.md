# Threat Model (Draft)

This document captures the initial threat model for ZKAT Milestone 2. It will be
expanded alongside the zkVM implementation and formal verification work.

## Assets

- Canonical digest commitments.
- ZK receipts and their public outputs.
- Anchor evidence (DKIM email, Git commits).

## Primary threats

- Tampering with attestation payloads or receipts.
- Replaying receipts against different canonical inputs.
- Substituting unauthorized zkVM programs.

## Mitigations

- Commitment checks bind receipts to canonical digests.
- Signature and anchor validation detect payload tampering.
- Program hash pinning prevents unauthorized zkVM substitutions.
