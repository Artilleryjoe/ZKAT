"""Stub verifier for zkVM receipts."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any


def verify_receipt(receipt_b64: str, program_hash: str) -> dict[str, Any]:
    """Verify a zkVM receipt and return the public outputs."""

    try:
        receipt_bytes = base64.b64decode(receipt_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("ZK receipt is not valid Base64") from exc

    try:
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("ZK receipt is not valid JSON") from exc

    if receipt.get("program_hash") != program_hash:
        raise ValueError("ZK receipt program hash mismatch")

    public = receipt.get("public", {})
    if "commitment" not in public or "policy_ok" not in public:
        raise ValueError("ZK receipt missing required public outputs")

    return {
        "commitment_hex": public.get("commitment"),
        "policy_ok": public.get("policy_ok"),
        "policy_id": public.get("policy_id"),
    }
