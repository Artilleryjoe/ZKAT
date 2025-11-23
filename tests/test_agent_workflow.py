import base64
import json
import sys
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path

import pytest
from git import Repo

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from zkat.agent import email_anchor
from zkat.agent import canonicalize_nmap
from zkat.agent import pqc_sign
from zkat.agent import zkat_agent
from zkat.agent import git_anchor
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


def test_agent_updates_chain_tip(tmp_path):
    state_dir = tmp_path / "state"
    previous_tip = {"hash": "0" * 64, "run_id": "19700101T000000Z"}
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "chain_tip.json").write_text(json.dumps(previous_tip))

    artifacts = _execute_agent(tmp_path)

    attestation_doc = json.loads(artifacts["attestation"].read_text())
    assert attestation_doc["previous"] == previous_tip

    chain_tip = json.loads((state_dir / "chain_tip.json").read_text())
    assert chain_tip["hash"] == attestation_doc["digest"]["canonical_sha3_256"]
    assert chain_tip["run_id"] == attestation_doc["run_id"]


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


def test_verifier_rejects_digest_mismatch(tmp_path):
    artifacts = _execute_agent(tmp_path)

    attestation_path = artifacts["attestation"]
    signature_path = artifacts["signature"]
    canonical_path = artifacts["canonical"]
    email_path = artifacts["email"]

    message = BytesParser(policy=default_policy).parsebytes(email_path.read_bytes())
    message.replace_header("X-ZKAT-Digest", "0" * 64)
    email_path.write_bytes(message.as_bytes())

    with pytest.raises(SystemExit, match="Digest recorded in email does not match"):
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


def test_verifier_enforces_chain_tip(tmp_path):
    artifacts = _execute_agent(tmp_path)

    expected_previous = tmp_path / "expected_previous.json"
    expected_previous.write_text(json.dumps({"hash": "bad", "run_id": "run"}))

    with pytest.raises(SystemExit, match="chain tip"):
        zkat_verify.main(
            [
                "--attestation",
                str(artifacts["attestation"]),
                "--signature",
                str(artifacts["signature"]),
                "--canonical",
                str(artifacts["canonical"]),
                "--email",
                str(artifacts["email"]),
                "--expected-previous",
                str(expected_previous),
            ]
        )


def test_git_anchor_creates_commit(tmp_path):
    repo_path = tmp_path / "repo"
    repo = Repo.init(repo_path, initial_branch="main")
    config = repo.config_writer()
    config.set_value("user", "name", "ZKAT Tester")
    config.set_value("user", "email", "tester@example.com")
    config.release()

    attestation_file = repo_path / "attestation.json"
    attestation_file.write_text("{}")

    result = git_anchor.commit_attestation(repo_path, attestation_file, "Add attestation", branch="main")

    assert repo.head.commit.hexsha == result["commit"]
    assert repo.head.reference.name == "main"
    assert Path(repo_path / result["path"]).exists()
