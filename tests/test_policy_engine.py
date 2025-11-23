import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from zkat.verifier.policy_engine import (
    ControlEvidence,
    ControlRequirement,
    PolicyEngine,
    evaluate_attestation_chain,
    validate_chain,
)


def _make_attestation(control_id: str, version: str, run_id: str, previous: dict[str, str | None]):
    canonical = {"control": control_id, "run_id": run_id}
    canonical_bytes = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = hashlib.sha3_256(canonical_bytes).hexdigest()
    return {
        "$schema": "https://example.com/zkat/attestation.schema.json",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "control": {"id": control_id, "version": version},
        "digest": {"canonical_sha3_256": digest},
        "previous": previous,
        "canonical": canonical,
        "nmap": {},
    }


def test_policy_flags_missing_control():
    policy = PolicyEngine({
        "required-control": ControlRequirement(required=True),
        "optional-control": ControlRequirement(required=False),
    })
    evidence = [
        ControlEvidence(
            control_id="optional-control",
            generated_at=datetime.now(timezone.utc),
            version="1.0.0",
        )
    ]

    result = policy.evaluate(evidence)

    assert not result.passed
    assert "Missing required control: required-control" in result.errors


def test_policy_rejects_stale_version_and_age():
    policy = PolicyEngine({
        "network-scan": ControlRequirement(min_version="2.0.0", fresh_within=timedelta(minutes=5)),
    })
    old_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    evidence = [ControlEvidence(control_id="network-scan", generated_at=old_time, version="1.5.0")]

    result = policy.evaluate(evidence, now=datetime.now(timezone.utc))

    assert not result.passed
    assert any("below the minimum" in err for err in result.errors)
    assert any("stale" in err for err in result.errors)


def test_validate_chain_detects_breakage():
    first = _make_attestation("control-a", "1.0.0", "run-a", {"hash": None, "run_id": None})
    second = _make_attestation("control-b", "1.0.0", "run-b", {"hash": "bad", "run_id": "wrong"})

    with pytest.raises(ValueError, match="Broken attestation chain"):
        validate_chain([first, second])


def test_end_to_end_policy_with_chain_continuity():
    first = _make_attestation("control-a", "1.2.0", "run-a", {"hash": None, "run_id": None})
    second_previous = {
        "hash": first["digest"]["canonical_sha3_256"],
        "run_id": first["run_id"],
    }
    second = _make_attestation("control-b", "2.1.0", "run-b", second_previous)

    policy = PolicyEngine(
        {
            "control-a": ControlRequirement(min_version="1.0.0", fresh_within=timedelta(hours=1)),
            "control-b": ControlRequirement(required=True, min_version="2.0.0"),
        }
    )

    result = evaluate_attestation_chain([first, second], policy, now=datetime.now(timezone.utc))

    assert result.passed
    assert not result.errors
