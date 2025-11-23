# Milestone 2 Design: Extensible, Chain-Hardened Attestations

Milestone 2 expands ZKAT beyond a single Nmap control into a pluggable, multi-control pipeline
with stronger hash-chain guarantees and a more automatable verifier experience. This document
covers the chain-hardening model, the control plugin architecture, verifier flow, and migration
notes for integrators. It also includes example configuration snippets and expected outputs for
multi-control attestations.

## Chain-Hardening Model

The chain aims to make every attestation tamper-evident and temporally anchored while keeping
agent state minimal.

- **Unbroken hash chain:** Each attestation embeds the SHA3-256 hash of the previous finalized
  attestation (`previous_hash`) plus the previous run identifier (`previous_run_id`). Missing or
  mismatched links cause verifier failure.
- **Monotonic sequencing:** The agent assigns a strictly increasing `sequence` counter that is
  included in the signed payload and mirrored in the anchors. The verifier rejects replays or
  forks where sequence numbers regress or skip unexpectedly.
- **Anchored across trust domains:** Each run emits at least two anchors (e.g., DKIM email and Git
  commit). Anchors contain the signed payload digest, run identifier, and sequence number so a
  verifier can cross-check artifacts without relying on the agent host.
- **Chain-backed logging:** Control-level logs are hashed into the canonical payload and included
  in the attestation digest. This lets verifiers detect truncation or tampering in per-control
  traces even when logs are stored off-host.
- **Failure codification:** If a control fails to run or produces non-compliant output, the agent
  records a structured `failure` object that is still chained and anchored. This preserves audit
  continuity instead of silently skipping a control.

## Plugin Architecture for Controls

Controls become plugins that share a common lifecycle and schema.

- **Control interface:** Each plugin exposes `prepare(config)`, `execute()`, and `summarize()`
  methods. `summarize()` returns canonicalizable JSON (inputs, findings, logs digest) that flows
  into the attestation payload.
- **Registration:** Plugins are registered through an entry point group (e.g.,
  `zkat.controls`). Integrators add a new control by publishing a package that advertises
  `entry_points={"zkat.controls": ["mycontrol=zkat_mycontrol.plugin:MyControl"]}`. The agent loads
  all discovered entry points at startup and applies per-run configuration.
- **Isolation:** Each plugin executes in its own working directory under `out/<run-id>/<control>/`
  so artifacts remain scoped. Temporary files are referenced by content hash inside the
  canonical payload.
- **Typed configuration:** Controls declare a `schema` attribute (JSON Schema draft-07). The agent
  validates the control-specific config before execution to prevent malformed runs.
- **Deterministic serialization:** All plugin outputs are canonicalized (stable key ordering,
  normalized timestamps, stripped environment-specific paths) before hashing and signing.

## Verifier Flow

The verifier now accepts multiple controls per attestation and enforces chain continuity.

1. **Load inputs:** Read `attestation.json`, `signature.json`, per-control canonical payloads, and
   anchors (email/Git). Optionally re-canonicalize raw control outputs when provided.
2. **Schema + plugin map:** Validate the attestation against the global schema, including the list
   of controls and their declared schemas. Verify that each control in the attestation matches a
   known plugin identifier.
3. **Digest reconstruction:** Recompute SHA3-256 over the canonical attestation payload, including
   embedded control summaries and the `previous_hash`/`sequence` fields.
4. **Signature validation:** Check the Dilithium2 signature over the canonical payload. Reject if
   the signer identity does not match the attested key or if the payload has been mutated.
5. **Chain continuity:** Compare `previous_hash` and `previous_run_id` with the verifier’s expected
   chain tip. Reject forks, regressions, or reuse of sequence numbers.
6. **Anchor confirmation:** Validate DKIM on the email anchor and confirm the Git commit references
   the same digest/run-id/sequence. Timestamp sanity checks ensure anchors are close to the
   attestation’s claimed time.
7. **Control-level integrity:** For each control, recompute the per-control digest (including
   log-hash) and ensure it matches the attestation payload. Surface any control-level failure
   objects alongside success results.

## Migration Notes for Integrators

### Registering New Controls

1. **Package the plugin:** Export a class implementing the control interface and include the JSON
   Schema for its configuration.
2. **Advertise entry point:** Add an entry under `zkat.controls` in `pyproject.toml` or
   `setup.cfg`, pointing to the control class.
3. **Distribute and install:** Publish to your package index; the agent will auto-discover it via
   entry points on the next run.
4. **Configure per environment:** Provide YAML/JSON config referencing the control by its entry
   point name and supply the control-specific settings. The agent will validate against the
   declared schema before execution.

### Enabling Chain-Backed Logging

- **Emit structured logs:** Controls should emit structured log events (e.g., JSON lines) and write
  them to `out/<run-id>/<control>/logs.jsonl`.
- **Hash before attestation:** The agent computes SHA3-256 over the log file and stores the digest
  in the control summary (`log_digest`).
- **Verifier enforcement:** During verification the recomputed log hash must match the recorded
  digest; mismatches cause verification failure, alerting integrators to tampering or truncation.

## Example Configurations and Expected Outputs

### Multi-Control Attestation (YAML)

```yaml
run_id: 2024-08-01-us-east
sequence: 17
previous_hash: "3c7a...ea9c"
controls:
  - name: nmap_smb
    plugin: nmap
    config:
      target: files/targets/smb_hosts.txt
      ports: [139, 445]
  - name: vuln_scan
    plugin: osv
    config:
      sbom: files/sbom.json
      severity_cutoff: high
```

### Expected Attestation Payload (excerpt)

```json
{
  "run_id": "2024-08-01-us-east",
  "sequence": 17,
  "previous_hash": "3c7a...ea9c",
  "controls": [
    {
      "name": "nmap_smb",
      "plugin": "nmap",
      "summary": {
        "targets": 12,
        "open_ports": [139, 445],
        "log_digest": "a1b2...ff09"
      }
    },
    {
      "name": "vuln_scan",
      "plugin": "osv",
      "summary": {
        "packages": 124,
        "critical_findings": 1,
        "log_digest": "09de...e311"
      }
    }
  ]
}
```

### Expected Verifier Output (console)

```
[ok] chain continuity: previous_hash matches local tip
[ok] signature: dilithium2 signature valid for run 2024-08-01-us-east
[ok] anchors: DKIM + Git digest agreement
[ok] control nmap_smb: summary + log hash verified
[ok] control vuln_scan: summary + log hash verified
```

These examples illustrate how multiple controls can be combined while preserving chain continuity,
per-control integrity, and cross-domain anchoring in Milestone 2.
