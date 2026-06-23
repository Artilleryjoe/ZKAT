# ZKAT

Zero-Knowledge Audit Trails (ZKAT) is an audit-attestation prototype focused on producing
signed, tamper-evident evidence for security control outcomes. Each run produces a signed digest,
anchors it across independent systems (Email DKIM, Git), and chains it for continuity so
verifiers can confirm integrity and provenance without handling raw logs.

> **Current status:** Milestone 2 is implemented as an end-to-end prototype. ZKAT now generates
> signed and anchored attestations, records chain continuity, embeds structured control results,
> and can require a zero-knowledge-style policy receipt during verification. The current zkVM path
> still uses scaffolded receipts and a placeholder program identifier, so it validates data binding
> and verifier behavior but is not production cryptographic assurance.

## Milestones

- **M1 (complete):** Signed + anchored digests (DKIM-ready email + Git) with chain continuity.
- **M2 (prototype complete):** Policy receipts bind a verifier-visible policy result to the same
  canonical SHA3-256 commitment used by the attestation. The verifier can enforce these receipts
  with `--require-zk` and rejects missing, malformed, mismatched, or wrong-program proof blocks.
- **Next production step:** Replace the local stub receipt generator and placeholder program ID with
  real zkVM proving artifacts, then publish production readiness criteria for proof generation,
  verifier allow-listing, and operational key management.

## Milestone 2 Scope and Prototype Boundary

Milestone 2 extends the Milestone 1 workflow with a zero-knowledge receipt flow for port-exposure
policies. The current implementation is designed for architecture validation and test coverage, not
production cryptographic assurance. The major components are:

- **Agent pipeline** that executes Nmap or consumes fixture XML, canonicalizes the relevant port
  evidence, computes a SHA3-256 digest, evaluates a configurable forbidden-port policy, generates a
  **stub zkVM receipt** binding the policy outcome to the same canonical digest, signs the canonical
  attestation payload with a Dilithium2-compatible signature record, emits structured control
  results, appends email plus optional Git anchors, persists artifacts, and updates local chain
  state.
- **Anchors** consisting of a DKIM-ready email containing the signed payload and an optional Git
  commit referencing the final attestation. These anchors provide independent, tamper-evident
  evidence of the attestation’s existence.
- **Verifier** capable of rebuilding the canonical payload, checking schema compliance, validating
  the post-quantum signature, confirming hash-chain continuity, inspecting the email/Git anchor
  metadata supplied by the caller, and checking temporal sanity. With `--require-zk`, the verifier
  also enforces the presence and validity of the receipt, ensures the published policy bit matches
  the receipt output, and re-evaluates the policy against the canonical projection.
- **Control-result framework** that records probe metadata, collection time, status, and structured
  evidence in the attestation. Built-in probes currently include baseline and Nmap evidence plus
  pending Sysdig, osquery, and cloud-posture stubs for future evidence sources.

Acceptance coverage includes expected-success and expected-failure scenarios for signatures, anchor
payloads, chain continuity, malformed Base64, public-key substitution, configurable policies, control
probe output, and ZK commitment/program binding.

## Repository Layout

```
zkat/
  agent/
    controls/
      base.py
      probes.py
    zk/
      prove_policy.py
      policy_inputs.py
    canonicalize_nmap.py
    email_anchor.py
    git_anchor.py
    pqc_sign.py
    zkat_agent.py
  verifier/
    zk/
      verify_receipt.py
    policy_engine.py
    zkat_verify.py
  zk/
    policy_checker/
      README.md
      src/...
    artifacts/
      program_id.txt
  schema/
    attestation.schema.json
  docs/
    milestones.md
    threat_model.md
    zk_design.md
  chain/
    log.py
  state/
    chain_tip.json
  out/
    .gitkeep
pyproject.toml
README.md
```

## Zero-knowledge policy proof (Current Prototype)

The agent defaults to the `no_smb_exposed` policy by checking that ports 139 and 445 are not marked
`open` in the canonical projection. The same policy engine can also load a JSON policy definition
with `--policy` for other forbidden-port checks. For example, certificate, firewall, dependency, or
service-exposure controls that canonicalize their evidence into port-style findings can define their
own policy identifier and forbidden ports.

A local **stub** zkVM receipt is generated with public output for the policy identifier, policy
result, program hash, and canonical-input commitment. The attestation records this under `zk_proof`
with the placeholder program identifier stored in `zkat/zk/artifacts/program_id.txt`. Verifiers
recompute the canonical digest, confirm it matches `digest.canonical_sha3_256` and
`result_commitment.digest_hex`, verify that `zk_proof.input_commitment.digest_hex` matches the same
commitment, decode the receipt, and ensure the receipt public output aligns with the attested policy
block and canonicalized port states.

Passing `--require-zk` forces verification to fail when the proof is missing or inconsistent. This
demonstrates binding and verifier logic, but should be treated as a **ZK roadmap prototype** rather
than a deployed production zkVM integration. The placeholder program ID is intentional until the
Risc0 integration lands; at that point `zkat/zk/artifacts/program_id.txt`, receipt generation, and
verifier checks should be updated together with the real image ID and proving artifacts.

## Strategy and Roadmap

Near-term roadmap:

- Preserve the implemented M1 attestation/verifier workflow as the stable core.
- Promote the M2 stub receipt flow to real zkVM proving and verification artifacts.
- Expand concrete control probes beyond the current baseline/Nmap implementation and pending
  Sysdig, osquery, and cloud-posture placeholders.
- Keep explicit verifier failure-path coverage for signatures, anchors, schema, chain continuity,
  public-key binding, and proof binding.
- Document production-readiness criteria separately from prototype milestones.

## Local development

Install ZKAT in editable mode with its development extras before running tests, schema validation
helpers, or CI-equivalent checks:

```bash
pip install -e '.[dev]'
```

The `dev` extra installs the optional validation and test dependencies declared in `pyproject.toml`.

## Health checks

Run the health checker before local development or release validation:

```bash
python -m zkat.health --json
```

The command exits non-zero only for failing checks. Warning results are intentionally advisory and
identify prototype or environment-specific gaps that may not block fixture-based development:

- `optional-modules`: run `pip install -e '.[dev]'` when JSON Schema validation helpers or optional
  crypto adapters are needed.
- `zk-program-id`: expected while the Milestone 2 zkVM path still uses placeholder proving artifacts.
- `nmap`: install the `nmap` binary for live scans, or continue using `--nmap-xml` fixtures for
  hermetic runs.

## Running the agent

The Milestone 2 agent accepts either a live `nmap` target or a pre-recorded XML file and produces a
signed attestation bundle under `out/<run-id>/`. The examples below reuse the sample Nmap output from
`tests/data/sample_nmap.xml` so the workflow remains hermetic.

```bash
python -m zkat.agent.zkat_agent \
  --nmap-xml tests/data/sample_nmap.xml \
  --output-dir ./out \
  --state-dir ./state \
  --private-key ./state/agent.key \
  --skip-git
```

Each run writes:

- `canonical.json`: canonicalized projection of the Nmap XML covering policy-relevant ports.
- `attestation.json`: signed payload content with digest, result commitment, control results,
  receipt block, chain tip, and embedded canonical JSON.
- `signature.json`: Dilithium2-compatible signature record with the public key used by the verifier.
- `email/*.eml`: DKIM-ready anchor email containing the Base64 payload, unless `--skip-email` is set.
- `summary.json`: convenience pointer to the generated artifacts.

### Custom forbidden-port policies

Pass `--policy path/to/policy.json` to replace the default SMB exposure policy. Supported policy
files currently use the `forbidden_open_ports` type:

```json
{
  "id": "no_http_exposed",
  "type": "forbidden_open_ports",
  "forbidden_ports": [80],
  "description": "HTTP must not be open"
}
```

The policy definition is embedded in the ZK public block, included in the receipt output by policy
ID, and re-evaluated by the verifier when `--require-zk` is used.

## Verifying an attestation

The verifier rebuilds the canonical payload, checks the SHA3-256 digest, validates the signature,
ensures timestamps are well-formed, optionally validates the schema and anchor email integrity,
checks the expected previous chain tip when supplied, and enforces the proof block when
`--require-zk` is configured.

```bash
python -m zkat.verifier.zkat_verify \
  --attestation out/<run-id>/attestation.json \
  --signature out/<run-id>/signature.json \
  --canonical out/<run-id>/canonical.json \
  --email out/<run-id>/email/<run-id>.eml \
  --expected-previous state/chain_tip.json \
  --require-zk
```

Provide `--nmap-xml` instead of `--canonical` to re-canonicalize a raw Nmap XML input. The default
JSON Schema is bundled under `zkat/schema/attestation.schema.json`. When supplying
`--expected-previous`, the verifier enforces continuity with the hash/run-id recorded from the prior
attestation, allowing a full audit trail to be validated without trusting agent-local state.

## How verification works (M2)

- Canonicalize the Nmap input to stable JSON bytes, or load canonical bytes emitted by the agent.
- Hash the canonical bytes to derive the SHA3-256 result commitment.
- Compare the result commitment against the attestation digest and `result_commitment` block.
- Verify the Dilithium2-compatible signature over the attestation payload.
- Confirm the signature public key matches the public key embedded in the attestation.
- Validate chain continuity via the `previous` pointer when `--expected-previous` is supplied.
- Inspect email anchor integrity when an anchor email is supplied.
- Validate schema shape when `jsonschema` is installed.
- Enforce `--require-zk` if configured.
- Verify the receipt against `program_hash` and the local expected program ID.
- Compare the receipt’s policy bit and policy ID to the attested public output.
- Re-evaluate the policy over the canonical projection and reject mismatched receipt results.

## Control probes

Control probes provide an extension point for adding evidence sources without changing the core
attestation envelope. Each probe emits:

- `control_id`
- `metadata.source`, `metadata.version`, and `metadata.trust_domain`
- `status`
- `collected_at`
- structured `evidence` entries

The current built-ins are:

- `placeholder.baseline`: records a baseline local run marker.
- `network.nmap.canonical`: records the canonical Nmap evidence and digest.
- `runtime.sysdig`, `runtime.osquery`, and `cloud.posture`: pending placeholders that document the
  next evidence-source integration points.
