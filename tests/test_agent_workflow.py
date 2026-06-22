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
        "private_key": private_key_path,
    }


def test_canonicalize_filters_ports():
    xml_bytes = (FIXTURE_DIR / "sample_nmap.xml").read_bytes()
    canonical = json.loads(canonicalize_nmap.canon_ports_139_445(xml_bytes).decode("utf-8"))
    hosts = canonical["hosts"]
    assert len(hosts) == 1
    ports = hosts[0]["ports"]
    assert [port["portid"] for port in ports] == [139, 445]
    assert ports[0]["service"]["name"] == "netbios-ssn"


def test_canonicalize_orders_duplicate_port_numbers_by_protocol():
    xml_template = """
    <nmaprun scanner="nmap">
      <host>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <ports>
          {ports}
        </ports>
      </host>
    </nmaprun>
    """
    tcp_port = '<port protocol="tcp" portid="445"><state state="closed" reason="reset"/></port>'
    udp_port = '<port protocol="udp" portid="445"><state state="open" reason="udp-response"/></port>'

    tcp_first = canonicalize_nmap.canon_ports_139_445(
        xml_template.format(ports=tcp_port + udp_port).encode("utf-8")
    )
    udp_first = canonicalize_nmap.canon_ports_139_445(
        xml_template.format(ports=udp_port + tcp_port).encode("utf-8")
    )

    assert tcp_first == udp_first
    ports = json.loads(tcp_first.decode("utf-8"))["hosts"][0]["ports"]
    assert [(port["portid"], port["protocol"]) for port in ports] == [(445, "tcp"), (445, "udp")]


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
    assert attestation_doc["result_commitment"]["digest_hex"] == attestation_doc["digest"][
        "canonical_sha3_256"
    ]
    assert attestation_doc["zk_proof"]["input_commitment"]["digest_hex"] == attestation_doc[
        "result_commitment"
    ]["digest_hex"]

    controls = attestation_doc.get("controls", [])
    assert controls, "Attestation should include control results"
    assert controls[0]["control_id"] == "placeholder.baseline"

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
            "--require-zk",
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


def test_verifier_rejects_malformed_email_payload_base64(tmp_path):
    artifacts = _execute_agent(tmp_path)

    email_path = artifacts["email"]
    email_bytes = email_path.read_bytes()
    record = email_anchor.parse_anchor_email(email_bytes)
    parser = BytesParser(policy=default_policy)
    message = parser.parsebytes(email_bytes)
    body = message.get_body(preferencelist=("plain",)).get_content()
    malformed_payload = "!!not-base64!!"
    tampered_body = body.replace(
        f"Payload-Base64: {record['payload_b64']}",
        f"Payload-Base64: {malformed_payload}",
    )
    message.set_content(tampered_body)
    email_path.write_bytes(message.as_bytes())

    with pytest.raises(SystemExit, match="payload is not valid Base64"):
        zkat_verify.main(
            [
                "--attestation",
                str(artifacts["attestation"]),
                "--signature",
                str(artifacts["signature"]),
                "--canonical",
                str(artifacts["canonical"]),
                "--email",
                str(email_path),
            ]
        )


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


def test_verifier_rejects_signature_key_substitution(tmp_path):
    artifacts = _execute_agent(tmp_path)

    attestation_bytes = artifacts["attestation"].read_bytes()
    attacker_private_key = b"attacker-private-key" * 4
    attacker_public_key = pqc_sign.derive_public_key(attacker_private_key)
    substituted_signature = {
        "algorithm": "sha3-512-simd-dilithium2-compatible",
        "signature": pqc_sign.sign_dilithium2(attacker_private_key, attestation_bytes),
        "public_key": base64.b64encode(attacker_public_key).decode("ascii"),
        "payload": artifacts["attestation"].name,
    }
    substituted_signature_path = artifacts["run_dir"] / "substituted_signature.json"
    substituted_signature_path.write_text(json.dumps(substituted_signature, indent=2))

    with pytest.raises(SystemExit, match="public key does not match attestation public key"):
        zkat_verify.main(
            [
                "--attestation",
                str(artifacts["attestation"]),
                "--signature",
                str(substituted_signature_path),
                "--canonical",
                str(artifacts["canonical"]),
            ]
        )


def test_verifier_rejects_mismatched_zk_commitment(tmp_path):
    artifacts = _execute_agent(tmp_path)

    attestation_doc = json.loads(artifacts["attestation"].read_text())
    attestation_doc["zk_proof"]["input_commitment"]["digest_hex"] = "0" * 64
    tampered_path = artifacts["run_dir"] / "tampered_attestation.json"
    tampered_bytes = json.dumps(attestation_doc, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    tampered_path.write_bytes(tampered_bytes)

    private_key = artifacts["private_key"].read_bytes()
    signature_doc = json.loads(artifacts["signature"].read_text())
    signature_doc["signature"] = pqc_sign.sign_dilithium2(private_key, tampered_bytes)
    signature_doc["payload"] = tampered_path.name
    tampered_signature_path = artifacts["run_dir"] / "tampered_signature.json"
    tampered_signature_path.write_text(json.dumps(signature_doc, indent=2))

    with pytest.raises(SystemExit, match="ZK proof input commitment does not match result commitment"):
        zkat_verify.main(
            [
                "--attestation",
                str(tampered_path),
                "--signature",
                str(tampered_signature_path),
                "--canonical",
                str(artifacts["canonical"]),
                "--require-zk",
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


def test_prepare_run_directory_avoids_timestamp_collisions(tmp_path, monkeypatch):
    class FixedDateTime:
        @classmethod
        def now(cls, tz=None):
            from datetime import datetime

            return datetime(2026, 6, 22, 12, 0, 0, tzinfo=tz)

    monkeypatch.setattr(zkat_agent, "datetime", FixedDateTime)

    first_run_id, first_run_dir = zkat_agent._prepare_run_directory(tmp_path)
    second_run_id, second_run_dir = zkat_agent._prepare_run_directory(tmp_path)

    assert first_run_id == "20260622T120000Z"
    assert second_run_id.startswith("20260622T120000Z-")
    assert first_run_dir.exists()
    assert second_run_dir.exists()
    assert first_run_dir != second_run_dir


def test_git_anchor_rejects_files_outside_repository(tmp_path):
    repo_path = tmp_path / "repo"
    repo = Repo.init(repo_path, initial_branch="main")
    config = repo.config_writer()
    config.set_value("user", "name", "ZKAT Tester")
    config.set_value("user", "email", "tester@example.com")
    config.release()

    outside_file = tmp_path / "attestation.json"
    outside_file.write_text("{}")

    with pytest.raises(ValueError, match="inside the Git repository"):
        git_anchor.commit_attestation(repo_path, outside_file, "Add attestation", branch="main")
