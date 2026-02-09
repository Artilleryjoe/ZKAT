"""Canonical input helpers for ZK policy proofs."""

from __future__ import annotations

import hashlib
from typing import Any


def build_policy_input(canonical_bytes: bytes, policy_id: str) -> dict[str, Any]:
    """Return the canonical policy input structure used by the zkVM program."""

    return {
        "policy_id": policy_id,
        "result_commitment": {
            "algorithm": "SHA3-256",
            "digest_hex": hashlib.sha3_256(canonical_bytes).hexdigest(),
        },
    }


def input_commitment_hex(policy_input: dict[str, Any]) -> str:
    """Derive the commitment that binds the proof to the canonical input."""

    return policy_input["result_commitment"]["digest_hex"]
