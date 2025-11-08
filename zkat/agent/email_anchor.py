"""Email anchoring utilities for Milestone 1 attestations.

The production agent does not send live email – it instead writes EML files to
the output directory.  This keeps the workflow hermetic and suitable for unit
tests while still capturing all of the headers and body content that verifiers
need to inspect.
"""

from __future__ import annotations

import base64
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path
from typing import Any
from uuid import uuid4


def send_anchor_email(
    run_id: str,
    digest_hex: str,
    payload: bytes,
    *,
    out_dir: Path,
    sender: str = "zkat-agent@example.com",
    recipient: str = "zkat-auditor@example.com",
) -> Path:
    """Create a local EML file representing the anchor email.

    Args:
        run_id: Identifier for the attestation run.
        digest_hex: Canonical digest for the attestation payload.
        payload: Raw attestation payload (pre-signature).
        out_dir: Directory where the EML file should be written.
        sender: Envelope/From address for the anchor email.
        recipient: Destination address for the anchor email.

    Returns:
        Path to the generated EML file.
    """

    out_dir.mkdir(parents=True, exist_ok=True)
    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = f"ZKAT attestation {run_id}"
    message["Message-Id"] = f"<{uuid4()}@zkat.local>"
    message["X-ZKAT-Run-Id"] = run_id
    message["X-ZKAT-Digest"] = digest_hex

    payload_b64 = base64.b64encode(payload).decode("ascii")
    body = (
        "Zero-Knowledge Audit Trail anchor\n"
        f"Run-ID: {run_id}\n"
        f"Digest: {digest_hex}\n"
        "\n"
        "The attestation payload is attached below in Base64 form so verifiers\n"
        "can reconstruct the signed content without accessing the raw scan\n"
        "artifacts.\n"
        "\n"
        f"Payload-Base64: {payload_b64}\n"
    )
    message.set_content(body)

    eml_path = out_dir / f"{run_id}.eml"
    eml_path.write_bytes(message.as_bytes())
    return eml_path


def parse_anchor_email(eml_bytes: bytes) -> dict[str, Any]:
    """Extract metadata from a stored anchor email."""

    parser = BytesParser(policy=default_policy)
    message = parser.parsebytes(eml_bytes)

    payload_b64 = None
    for line in message.get_body(preferencelist=("plain",)).get_content().splitlines():
        if line.startswith("Payload-Base64:"):
            payload_b64 = line.split(":", 1)[1].strip()
            break

    return {
        "run_id": message.get("X-ZKAT-Run-Id"),
        "digest": message.get("X-ZKAT-Digest"),
        "message_id": message.get("Message-Id"),
        "subject": message.get("Subject"),
        "payload_b64": payload_b64,
    }


__all__ = [
    "send_anchor_email",
    "parse_anchor_email",
]
