import base64
import json
import sys
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from zkat.agent import email_anchor
from zkat.agent import canonicalize_nmap
from zkat.agent import pqc_sign
from zkat.agent import zkat_agent
from zkat.verifier import zkat_verify


FIXTURE_DIR = Path(__file__).parent / "data"


def _execute_agent(tmp_path: Path) -> dict[str, Path]:
    output_dir = tmp_path / "out"
    state_dir = tmp_path / "state"
    private_key_path = state_dir / "agent.key"

    zkat_agent.main(
        [
            "--nmap-xml",
            str(FIXTURE_DIR / "sample_nmap.xml"),
            "--output-dir",
            str(output_dir),
            "--state-dir",
            str(state_dir),
            "--private-key",
            str(private_key_path),
            "--skip-git",
        ]
    )

    run_dirs = list(output_dir.iterdir())
    assert len(run_dirs) == 1
    run_dir = run_dirs[0]

    email_dir = run_dir / "email"
    email_files = list(email_dir.glob("*.eml"))
    assert email_files, "Email anchor should be generated"

    return {
        "run_dir": run_dir,
        "attestation": run_dir / "attestation.json",
        "signature": run_dir / "signature.json",
        "canonical": run_dir / "canonical.json",
        "email": email_files[0],
    }


def test_canonicalize_filters_ports():
    xml_bytes = (FIXTURE_DIR / "sample_nmap.xml").read_bytes()
    canonical = json.loads(canonicalize_nmap.canon_ports_139_445(xml_bytes).decode("utf-8"))
    hosts = canonical["hosts"]
    assert len(hosts) == 1
    ports = hosts[0]["ports"]
    assert [port["portid"] for port in ports] == [139, 445]
    assert ports[0]["service"]["name"] == "netbios-ssn"


def test_sign_and_verify_roundtrip():
    private_key = b"example-private-key" * 4
    public_key = pqc_sign.derive_public_key(private_key)
    message = b"hello world"
    signature = pqc_sign.sign_dilithium2(private_key, message)
    assert pqc_sign.verify_dilithium2(public_key, message, signature)


def test_agent_and_verifier_integration(tmp_path, capsys):
    artifacts = _execute_agent(tmp_path)
    run_dir = artifacts["run_dir"]
    attestation_path = artifacts["attestation"]
    signature_path = artifacts["signature"]
    email_path = artifacts["email"]

    attestation_doc = json.loads(attestation_path.read_text())
    signature_doc = json.loads(signature_path.read_text())
    assert attestation_doc["digest"]["canonical_sha3_256"]

    # Signature record should contain a base64-encoded public key.
    base64.b64decode(signature_doc["public_key"])  # raises on failure

    # Run verifier and ensure it reports success.
    zkat_verify.main(
        [
            "--attestation",
            str(attestation_path),
            "--signature",
            str(signature_path),
            "--canonical",
            str(artifacts["canonical"]),
            "--email",
            str(email_path),
        ]
    )

    out = capsys.readouterr().out
    assert "\"status\": \"ok\"" in out


def test_verifier_rejects_tampered_email_payload(tmp_path):
    artifacts = _execute_agent(tmp_path)

    attestation_path = artifacts["attestation"]
    signature_path = artifacts["signature"]
    canonical_path = artifacts["canonical"]
    email_path = artifacts["email"]

    email_bytes = email_path.read_bytes()
    record = email_anchor.parse_anchor_email(email_bytes)
    assert record["payload_b64"]
    tampered_payload = base64.b64encode(b"not-the-attestation").decode("ascii")
    parser = BytesParser(policy=default_policy)
    message = parser.parsebytes(email_bytes)
    body = message.get_body(preferencelist=("plain",)).get_content()
    tampered_body = body.replace(
        f"Payload-Base64: {record['payload_b64']}",
        f"Payload-Base64: {tampered_payload}",
    )
    message.set_content(tampered_body)
    email_path.write_bytes(message.as_bytes())

    with pytest.raises(SystemExit, match="payload does not match"):
        zkat_verify.main(
            [
                "--attestation",
                str(attestation_path),
                "--signature",
                str(signature_path),
                "--canonical",
                str(canonical_path),
                "--email",
                str(email_path),
            ]
        )
