# ZKAT

Zero-Knowledge Audit Trails (ZKAT) is a lightweight, privacy-preserving, tamper-evident audit
trail for security controls. Each run produces a signed digest, anchored across independent
systems (Email DKIM, Git), and chained for continuity so verifiers can confirm proofs and anchors
without ever seeing raw logs.

## Milestone 1 Scope

Milestone 1 focuses on delivering an end-to-end attestation workflow for an SMB exposure check
using Nmap as the control primitive. The major components are:

- **Agent pipeline** that executes Nmap, canonicalizes its XML output, computes a SHA3-256 digest,
  signs the canonical attestation payload with Dilithium2, and appends email plus Git anchors
  before persisting artifacts and updating the local chain state.
- **Anchors** consisting of a DKIM-validated email containing the signed payload and a Git commit
  referencing the final attestation. These anchors provide independent, tamper-evident evidence of
  the attestation’s existence.
- **Verifier** capable of rebuilding the canonical payload, checking schema compliance, validating
  the post-quantum signature, confirming hash-chain continuity, and inspecting the email/Git
  anchors for authenticity and temporal sanity.

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

## Next Steps

Implementation will populate the placeholder modules with the Milestone 1 functionality described
above, accompanied by documentation and automated tests.
