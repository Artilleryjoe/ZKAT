"""Stub zkVM policy prover interface."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from .policy_inputs import (
    PortExposurePolicy,
    build_policy_input,
    evaluate_port_exposure_policy,
    input_commitment_hex,
)

PROGRAM_ID_PATH = Path(__file__).resolve().parents[2] / "zk" / "artifacts" / "program_id.txt"


def _load_program_hash() -> str:
    return PROGRAM_ID_PATH.read_text(encoding="utf-8").strip()


def prove_policy(canonical_bytes: bytes, policy: PortExposurePolicy) -> dict[str, Any]:
    """Return a stubbed zkVM proof bundle for the given canonical input."""

    canonical_document = json.loads(canonical_bytes.decode("utf-8"))
    policy_input = build_policy_input(canonical_bytes, policy)
    commitment_hex = input_commitment_hex(policy_input)
    policy_ok = evaluate_port_exposure_policy(canonical_document, policy)
    program_hash = _load_program_hash()

    receipt_payload = {
        "program_hash": program_hash,
        "public": {
            "policy_ok": policy_ok,
            "commitment": commitment_hex,
            "policy_id": policy.policy_id,
        },
    }
    receipt_bytes = json.dumps(receipt_payload, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )

    return {
        "program_hash": program_hash,
        "receipt_b64": base64.b64encode(receipt_bytes).decode("ascii"),
        "policy_ok": policy_ok,
        "input_commitment_hex": commitment_hex,
    }
