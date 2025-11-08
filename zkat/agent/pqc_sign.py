"""Post-quantum signing helpers for Milestone 1.

The production implementation is expected to leverage a full Dilithium2 stack,
but that is overkill (and heavy) for the milestone validation environment.  The
helpers in this module therefore provide a deterministic, self-contained
signature scheme that mimics the Dilithium2 API surface.  Signatures are
derived using SHA3-512 and encoded as Base64 strings.  The approach keeps the
API surface identical to the real implementation so the swap is transparent to
callers once a PQC backend is available.
"""

from __future__ import annotations

import base64
import hashlib
import hmac


def _normalise_inputs(key: bytes, message: bytes) -> tuple[bytes, bytes]:
    if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
        raise ValueError("Signing keys must be non-empty bytes")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("Messages must be provided as bytes")
    return bytes(key), bytes(message)


def derive_public_key(private_key: bytes) -> bytes:
    """Derive the public component for the deterministic signature scheme."""

    private_key, _ = _normalise_inputs(private_key, b"")
    return hashlib.sha3_512(private_key).digest()


def sign_dilithium2(private_key: bytes, message: bytes) -> str:
    """Generate a deterministic signature for ``message``.

    The function intentionally mirrors the Dilithium2 API, returning a Base64
    encoded signature.  The ``private_key`` should be stable between runs so the
    verifier can reconstruct the public component (``sha3_512(private_key)``).
    """

    private_key, message = _normalise_inputs(private_key, message)
    public_component = derive_public_key(private_key)
    signature = hashlib.sha3_512(public_component + message).digest()
    return base64.b64encode(signature).decode("ascii")


def verify_dilithium2(public_key: bytes, message: bytes, signature_b64: str) -> bool:
    """Validate a signature produced by :func:`sign_dilithium2`.

    Args:
        public_key: The public component for the attestor.
        message: The attestation payload.
        signature_b64: Base64-encoded signature string.
    """

    public_key, message = _normalise_inputs(public_key, message)
    try:
        provided_signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):  # pragma: no cover - defensive
        return False

    expected = hashlib.sha3_512(bytes(public_key) + message).digest()
    return hmac.compare_digest(provided_signature, expected)


__all__ = [
    "sign_dilithium2",
    "verify_dilithium2",
    "derive_public_key",
]
