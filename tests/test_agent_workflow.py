import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from zkat.agent import canonicalize_nmap
from zkat.agent import pqc_sign
from zkat.agent import zkat_agent
from zkat.verifier import zkat_verify


FIXTURE_DIR = Path(__file__).parent / "data"


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

    attestation_path = run_dir / "attestation.json"
    signature_path = run_dir / "signature.json"
    email_dir = run_dir / "email"
    email_files = list(email_dir.glob("*.eml"))
    assert email_files, "Email anchor should be generated"

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
            str(run_dir / "canonical.json"),
            "--email",
            str(email_files[0]),
        ]
    )

    out = capsys.readouterr().out
    assert "\"status\": \"ok\"" in out
