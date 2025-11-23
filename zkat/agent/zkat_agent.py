"""Entrypoint for the ZKAT Milestone 1 agent."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from .canonicalize_nmap import canon_ports_139_445
from .email_anchor import send_anchor_email
from .git_anchor import commit_attestation
from .pqc_sign import derive_public_key, sign_dilithium2


DEFAULT_SCHEMA = "https://example.com/zkat/attestation.schema.json"
CONTROL_ID = "nmap-139-445"
CONTROL_VERSION = "1.0.0"


@dataclass
class AgentConfig:
    target: str | None
    nmap_binary: str
    nmap_xml: Path | None
    output_dir: Path
    state_dir: Path
    private_key: Path
    public_key: Path | None
    skip_email: bool
    skip_git: bool
    email_from: str
    email_to: str
    git_repo: Path | None
    git_branch: str | None
    git_message: str


def _default_output_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "out"


def _default_state_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "state"


def _load_or_generate_key(path: Path, *, size: int = 64) -> bytes:
    if path.exists():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(size)
    path.write_bytes(key)
    return key


def _load_public_key(private_key: bytes, public_path: Path | None) -> tuple[bytes, Path | None]:
    derived = derive_public_key(private_key)
    if public_path is None:
        return derived, None

    if public_path.exists():
        return public_path.read_bytes(), public_path

    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_bytes(derived)
    return derived, public_path


def _load_chain_tip(state_dir: Path) -> dict[str, Any]:
    chain_path = state_dir / "chain_tip.json"
    if not chain_path.exists():
        return {"hash": None, "run_id": None}
    with chain_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_chain_tip(state_dir: Path, data: dict[str, Any]) -> Path:
    chain_path = state_dir / "chain_tip.json"
    state_dir.mkdir(parents=True, exist_ok=True)
    with chain_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
    return chain_path


def _run_nmap(binary: str, target: str, destination: Path) -> dict[str, Any]:
    command = [binary, "-p139,445", "-oX", str(destination), target]
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    return {
        "command": command,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
        "xml_path": str(destination),
    }


def _parse_args(argv: Sequence[str] | None) -> AgentConfig:
    parser = argparse.ArgumentParser(description="ZKAT Milestone 1 attestation agent")
    parser.add_argument("--target", help="Target passed to nmap (required unless --nmap-xml is provided)")
    parser.add_argument("--nmap-binary", default="nmap", help="Path to the nmap executable")
    parser.add_argument("--nmap-xml", type=Path, help="Existing Nmap XML file to reuse")
    parser.add_argument("--output-dir", type=Path, default=_default_output_dir())
    parser.add_argument("--state-dir", type=Path, default=_default_state_dir())
    parser.add_argument("--private-key", type=Path, default=_default_state_dir() / "agent.key")
    parser.add_argument("--public-key", type=Path, help="Path to the public key file")
    parser.add_argument("--skip-email", action="store_true", help="Do not generate an anchor email")
    parser.add_argument("--skip-git", action="store_true", help="Do not create a Git anchor commit")
    parser.add_argument("--email-from", default="zkat-agent@example.com")
    parser.add_argument("--email-to", default="zkat-auditor@example.com")
    parser.add_argument("--git-repo", type=Path, help="Repository used for Git anchoring")
    parser.add_argument("--git-branch", default="main", help="Branch updated by the Git anchor")
    parser.add_argument(
        "--git-message",
        default="ZKAT attestation {run_id}",
        help="Commit message template for Git anchoring",
    )

    args = parser.parse_args(argv)
    if not args.nmap_xml and not args.target:
        parser.error("either --target or --nmap-xml must be supplied")

    return AgentConfig(
        target=args.target,
        nmap_binary=args.nmap_binary,
        nmap_xml=args.nmap_xml,
        output_dir=args.output_dir,
        state_dir=args.state_dir,
        private_key=args.private_key,
        public_key=args.public_key,
        skip_email=args.skip_email,
        skip_git=args.skip_git,
        email_from=args.email_from,
        email_to=args.email_to,
        git_repo=args.git_repo,
        git_branch=args.git_branch,
        git_message=args.git_message,
    )


def _prepare_run_directory(base: Path) -> tuple[str, Path]:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = base / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)
    return timestamp, run_dir


def main(argv: Sequence[str] | None = None) -> None:
    config = _parse_args(argv)
    run_id, run_dir = _prepare_run_directory(config.output_dir)

    private_key = _load_or_generate_key(config.private_key)
    public_key, public_path = _load_public_key(private_key, config.public_key)

    nmap_info: dict[str, Any]
    if config.nmap_xml:
        xml_bytes = config.nmap_xml.read_bytes()
        nmap_info = {
            "source": "file",
            "xml_path": str(config.nmap_xml.resolve()),
        }
    else:
        xml_path = run_dir / "nmap.xml"
        target = config.target
        assert target is not None  # For type-checkers; enforced by argument parsing.
        nmap_info = _run_nmap(config.nmap_binary, target, xml_path)
        xml_bytes = xml_path.read_bytes()

    canonical_bytes = canon_ports_139_445(xml_bytes)
    canonical_path = run_dir / "canonical.json"
    canonical_path.write_bytes(canonical_bytes)

    digest_hex = hashlib.sha3_256(canonical_bytes).hexdigest()

    chain_tip = _load_chain_tip(config.state_dir)

    canonical_document = json.loads(canonical_bytes.decode("utf-8"))
    attestation = {
        "$schema": DEFAULT_SCHEMA,
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "control": {"id": CONTROL_ID, "version": CONTROL_VERSION},
        "target": config.target,
        "digest": {
            "canonical_sha3_256": digest_hex,
        },
        "previous": chain_tip,
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "canonical": canonical_document,
        "nmap": nmap_info,
        "artifacts": {
            "canonical": str(canonical_path),
            "run_dir": str(run_dir),
            "public_key": str(public_path) if public_path else None,
        },
    }

    payload_bytes = json.dumps(attestation, separators=(",", ":"), sort_keys=True).encode("utf-8")
    attestation_path = run_dir / "attestation.json"
    attestation_path.write_bytes(payload_bytes)

    signature_b64 = sign_dilithium2(private_key, payload_bytes)
    signature_record = {
        "algorithm": "sha3-512-simd-dilithium2-compatible",
        "signature": signature_b64,
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "payload": attestation_path.name,
    }
    signature_path = run_dir / "signature.json"
    signature_path.write_text(json.dumps(signature_record, indent=2))

    email_path: Path | None = None
    if not config.skip_email:
        email_dir = run_dir / "email"
        email_path = send_anchor_email(
            run_id,
            digest_hex,
            payload_bytes,
            out_dir=email_dir,
            sender=config.email_from,
            recipient=config.email_to,
        )

    git_info: dict[str, Any] | None = None
    if not config.skip_git and config.git_repo:
        message = config.git_message.format(run_id=run_id)
        git_info = commit_attestation(
            repo_path=config.git_repo,
            file_path=attestation_path,
            message=message,
            branch=config.git_branch,
        )

    _write_chain_tip(config.state_dir, {"hash": digest_hex, "run_id": run_id})

    summary = {
        "run_id": run_id,
        "attestation": str(attestation_path),
        "signature": signature_record,
        "email": str(email_path) if email_path else None,
        "git": git_info,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
