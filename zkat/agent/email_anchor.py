"""Email anchoring utilities for Milestone 1 attestations."""

from __future__ import annotations


def send_anchor_email(run_id: str, digest_hex: str, payload: bytes) -> None:
    """Placeholder for the outbound anchor email workflow."""
    raise NotImplementedError("Email anchoring not yet implemented")


def parse_anchor_email(eml_bytes: bytes) -> dict[str, str]:
    """Placeholder for extracting DKIM evidence from an anchor email."""
    raise NotImplementedError("Email anchor parsing not yet implemented")
