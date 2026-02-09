# Milestone 2 — ZK Policy Proof (Definition of Done)

- Agent generates `zk_proof.receipt` for the `no_smb_exposed` policy.
- Receipt verifies against `program_hash`.
- Receipt output binds to `result_commitment` via `input_commitment`.
- Verifier enforces `--require-zk` (fails if missing/invalid).
- End-to-end fixtures pass:
  - `policy_ok=true` case.
  - `policy_ok=false` case.
  - mismatched commitment case fails.
  - wrong `program_hash` case fails.
