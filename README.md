# ZKAT

Zero-Knowledge Audit Trails (ZKAT) is a lightweight, privacy-preserving, tamper-evident audit
trail for security controls. Each run produces a signed digest, anchored across independent
systems (Email DKIM, Git), and chained for continuity so verifiers can confirm proofs and anchors
without ever seeing raw logs.

## Milestone 2 Scope

Milestone 2 extends the Milestone 1 workflow with a zero-knowledge receipt that proves the SMB
policy result without revealing raw scan data. The major components are:

- **Agent pipeline** that executes Nmap, canonicalizes its XML output, computes a SHA3-256 digest,
  generates a zkVM receipt binding the policy outcome to the same canonical digest, signs the
  canonical attestation payload with Dilithium2, and appends email plus Git anchors before
  persisting artifacts and updating the local chain state.
- **Anchors** consisting of a DKIM-validated email containing the signed payload and a Git commit
  referencing the final attestation. These anchors provide independent, tamper-evident evidence of
  the attestation’s existence.
- **Verifier** capable of rebuilding the canonical payload, checking schema compliance, validating
  the post-quantum signature, confirming hash-chain continuity, and inspecting the email/Git
  anchors for authenticity and temporal sanity. With ``--require-zk`` the verifier also enforces
  the presence and validity of the zkVM receipt, ensuring the published policy bit matches the
  canonical digest.

Acceptance tests will cover expected-success and expected-failure scenarios, including signature,
anchor, and policy violations.

## Repository Layout

```
zkat/
  agent/
    canonicalize_nmap.py
    email_anchor.py
    git_anchor.py
    pqc_sign.py
    zkat_agent.py
  verifier/
    zkat_verify.py
  schema/
    attestation.schema.json
  state/
    chain_tip.json
  out/
    .gitkeep
pyproject.toml
README.md
```

## Zero-knowledge policy proof

The agent evaluates the policy "no_smb_exposed" by checking that ports 139 and 445 are not marked
``open`` in the canonical projection. A stub zkVM receipt is generated locally that exposes only
the boolean policy result and the SHA3-256 commitment over the canonical bytes. The attestation
records this under ``zk_proof`` with the program identifier
``zkvm-risc0-policy-checker-placeholder``. Verifiers recompute the canonical digest, confirm the
commitment matches ``digest.canonical_sha3_256``, and ensure the receipt’s public output aligns
with the canonicalized port states. Passing ``--require-zk`` forces verification to fail when the
proof is missing or inconsistent.

## Strategy and Roadmap

Roadmap details will be published once they are ready for public review.

## Running the agent

The Milestone 1 agent accepts either a live `nmap` target or a pre-recorded XML
file and produces a signed attestation bundle under `out/<run-id>/`.  The
examples below reuse the sample Nmap output from `tests/data/sample_nmap.xml`
so the workflow remains hermetic.

```
python -m zkat.agent.zkat_agent \
  --nmap-xml tests/data/sample_nmap.xml \
  --output-dir ./out \
  --state-dir ./state \
  --private-key ./state/agent.key \
  --skip-git
```

Each run writes:

- `canonical.json`: canonicalized projection of the Nmap XML covering ports 139/445
- `attestation.json`: payload with digest, chain tip, and embedded canonical JSON
- `signature.json`: deterministic Dilithium2-compatible signature record
- `email/*.eml`: DKIM-ready anchor email containing the Base64 payload
- `summary.json`: convenience pointer to the generated artifacts

## Verifying an attestation

The verifier rebuilds the canonical payload, checks the SHA3-256 digest,
validates the deterministic signature, ensures timestamps are well-formed, and
optionally validates the schema and anchor email integrity.

```
python -m zkat.verifier.zkat_verify \
  --attestation out/<run-id>/attestation.json \
  --signature out/<run-id>/signature.json \
  --canonical out/<run-id>/canonical.json \
  --email out/<run-id>/email/<run-id>.eml \
  --expected-previous state/chain_tip.json
```

Provide `--nmap-xml` instead of `--canonical` to re-canonicalize a raw Nmap XML
input. The default JSON Schema is bundled under `zkat/schema/attestation.schema.json`.
When supplying `--expected-previous` the verifier will enforce continuity with the
hash/run-id recorded from the prior attestation, allowing a full audit trail to be
validated without trusting agent-local state.
