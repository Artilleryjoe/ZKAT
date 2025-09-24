"""Post-quantum signing helpers for Milestone 1."""

from __future__ import annotations


def sign_dilithium2(private_key: bytes, message: bytes) -> str:
    """Placeholder for Dilithium2 signing."""
    raise NotImplementedError("Dilithium2 signing not yet implemented")


def verify_dilithium2(public_key: bytes, message: bytes, signature_b64: str) -> bool:
    """Placeholder for Dilithium2 signature verification."""
    raise NotImplementedError("Dilithium2 verification not yet implemented")
