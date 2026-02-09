# ZK Design Notes

## Canonical input format

The zkVM guest consumes a canonical JSON payload with the following structure:

```json
{
  "policy_id": "no_smb_exposed",
  "result_commitment": {
    "algorithm": "SHA3-256",
    "digest_hex": "<sha3-256 over canonical bytes>"
  }
}
```

The `result_commitment.digest_hex` is derived from the canonicalized Nmap
projection bytes (the same bytes stored in `canonical.json`).

## Public vs private

- **Private to the zkVM guest**: raw canonicalized host/port records.
- **Public outputs**: `policy_ok` and the `result_commitment` commitment.
- **Verifier-visible data**: `program_hash`, `input_commitment`, and the receipt.

## Binding conditions

- `result_commitment.digest_hex` equals the SHA3-256 of the canonical bytes.
- `zk_proof.input_commitment.digest_hex` equals `result_commitment.digest_hex`.
- The receipt public commitment equals `result_commitment.digest_hex`.
- The receipt public `policy_ok` matches the attested policy bit.

## Replay and tamper cases

- **Replay**: A receipt bound to a different canonical digest fails the
  commitment check.
- **Tamper**: Modifying `policy_ok` or `result_commitment` breaks the receipt
  or commitment checks.
- **Program mismatch**: Receipts compiled from a different zkVM guest are
  rejected because the `program_hash` changes.

## Upgrade strategy

- Every zkVM guest build publishes a new `program_hash` under
  `zkat/zk/artifacts/program_id.txt`.
- The attestation embeds the `program_hash` used during proof generation.
- Verifiers pin or allow-list program hashes; upgrades require explicit
  acceptance of the new hash.
