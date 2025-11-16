"""Verification routines for Milestone 1 attestations."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any, Sequence

from dateutil import parser as date_parser

from ..agent.email_anchor import parse_anchor_email
from ..agent.pqc_sign import verify_dilithium2
from ..agent.canonicalize_nmap import canon_ports_139_445

try:  # pragma: no cover - jsonschema is optional at runtime
    from jsonschema import Draft202012Validator
except Exception:  # pragma: no cover - optional dependency
    Draft202012Validator = None


def _default_schema_path() -> Path:
    return Path(__file__).resolve().parents[1] / "schema" / "attestation.schema.json"


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _dump_canonical(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _validate_schema(document: Any, schema_path: Path) -> list[str]:
    if Draft202012Validator is None:
        return []

    schema = _load_json(schema_path)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda err: err.path)
    return [f"{list(error.path)}: {error.message}" for error in errors]


def _derive_canonical_bytes(args: argparse.Namespace, attestation: dict[str, Any]) -> bytes:
    if args.canonical:
        return Path(args.canonical).read_bytes()
    if args.nmap_xml:
        xml_bytes = Path(args.nmap_xml).read_bytes()
        return canon_ports_139_445(xml_bytes)
    return _dump_canonical(attestation.get("canonical"))


def _load_public_key(args: argparse.Namespace, signature_record: dict[str, Any]) -> bytes:
    if args.public_key:
        return Path(args.public_key).read_bytes()
    if "public_key" in signature_record:
        return base64.b64decode(signature_record["public_key"])
    raise ValueError("No public key provided for signature verification")


def _verify_email(
    args: argparse.Namespace,
    attestation: dict[str, Any],
    attestation_bytes: bytes,
) -> dict[str, Any] | None:
    if not args.email:
        return None

    record = parse_anchor_email(Path(args.email).read_bytes())
    digest = attestation.get("digest", {}).get("canonical_sha3_256")
    if record.get("digest") != digest:
        raise ValueError("Digest recorded in email does not match attestation")

    payload_b64 = record.get("payload_b64")
    if not payload_b64:
        raise ValueError("Anchor email missing embedded payload")

    try:
        payload_bytes = base64.b64decode(payload_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Anchor email payload is not valid Base64") from exc

    if payload_bytes != attestation_bytes:
        raise ValueError("Anchor email payload does not match attestation")

    return record


def _verify_temporal_sanity(attestation: dict[str, Any]) -> None:
    generated_at = attestation.get("generated_at")
    if not generated_at:
        raise ValueError("Attestation missing generated_at timestamp")
    date_parser.isoparse(generated_at)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify a ZKAT attestation")
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--canonical", type=Path, help="Canonical JSON output from the agent")
    parser.add_argument("--nmap-xml", type=Path, help="Original Nmap XML to re-canonicalize")
    parser.add_argument("--email", type=Path, help="Anchor email to inspect")
    parser.add_argument("--schema", type=Path, default=_default_schema_path())
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    args = _parse_args(argv)

    attestation_path = Path(args.attestation)
    attestation_bytes = attestation_path.read_bytes()
    attestation = json.loads(attestation_bytes)
    signature_record = _load_json(args.signature)

    canonical_bytes = _derive_canonical_bytes(args, attestation)
    digest_hex = hashlib.sha3_256(canonical_bytes).hexdigest()
    recorded_digest = attestation.get("digest", {}).get("canonical_sha3_256")
    if recorded_digest != digest_hex:
        raise SystemExit("Canonical digest mismatch")

    public_key = _load_public_key(args, signature_record)
    signature_b64 = signature_record.get("signature")
    if not signature_b64:
        raise SystemExit("Signature record missing signature field")

    if not verify_dilithium2(public_key, attestation_bytes, signature_b64):
        raise SystemExit("Signature verification failed")

    _verify_temporal_sanity(attestation)

    schema_errors = _validate_schema(attestation, args.schema)
    if schema_errors:
        raise SystemExit("; ".join(schema_errors))

    try:
        email_record = _verify_email(args, attestation, attestation_bytes)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    print(
        json.dumps(
            {
                "status": "ok",
                "digest": digest_hex,
                "signature": signature_b64,
                "email": email_record,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
