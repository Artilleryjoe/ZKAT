"""Policy evaluation utilities for aggregated control evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

from dateutil import parser as date_parser
from packaging.version import Version


@dataclass(frozen=True)
class ControlEvidence:
    """Normalized control evidence extracted from an attestation."""

    control_id: str
    generated_at: datetime
    version: str

    @classmethod
    def from_attestation(cls, attestation: dict[str, Any]) -> "ControlEvidence":
        control = attestation.get("control")
        if not isinstance(control, dict):
            raise ValueError("Attestation missing control metadata")

        control_id = control.get("id")
        version = control.get("version")
        if not control_id or not version:
            raise ValueError("Control metadata must include id and version")

        generated_at_raw = attestation.get("generated_at")
        if not generated_at_raw:
            raise ValueError("Attestation missing generated_at timestamp")

        generated_at = date_parser.isoparse(generated_at_raw)
        if generated_at.tzinfo is None:
            generated_at = generated_at.replace(tzinfo=timezone.utc)

        return cls(control_id=control_id, generated_at=generated_at, version=version)


@dataclass(frozen=True)
class ControlRequirement:
    """Policy constraints for a single control."""

    required: bool = True
    min_version: str | None = None
    fresh_within: timedelta | None = None


@dataclass(frozen=True)
class PolicyResult:
    """Outcome of evaluating control evidence against a policy."""

    passed: bool
    errors: list[str]


class PolicyEngine:
    """Evaluate evidence for a set of controls against policy requirements."""

    def __init__(self, requirements: dict[str, ControlRequirement]):
        self._requirements = requirements

    def evaluate(
        self, evidence: Sequence[ControlEvidence], *, now: datetime | None = None
    ) -> PolicyResult:
        current_time = now or datetime.now(timezone.utc)
        evidence_by_id = {record.control_id: record for record in evidence}
        errors: list[str] = []

        for control_id, requirement in self._requirements.items():
            record = evidence_by_id.get(control_id)
            if record is None:
                if requirement.required:
                    errors.append(f"Missing required control: {control_id}")
                continue

            if requirement.min_version:
                if Version(record.version) < Version(requirement.min_version):
                    errors.append(
                        "Control {control_id} version {version} is below the minimum {minimum}".format(
                            control_id=control_id,
                            version=record.version,
                            minimum=requirement.min_version,
                        )
                    )

            if requirement.fresh_within:
                if record.generated_at < current_time - requirement.fresh_within:
                    errors.append(
                        "Control {control_id} evidence is stale (generated at {ts})".format(
                            control_id=control_id, ts=record.generated_at.isoformat()
                        )
                    )

        return PolicyResult(passed=not errors, errors=errors)


def validate_chain(attestations: Sequence[dict[str, Any]]) -> None:
    """Ensure hash-linked continuity across attestation documents.

    Raises a :class:`ValueError` if any attestation does not point to the
    canonical digest and run_id of its predecessor.
    """

    if not attestations:
        raise ValueError("No attestations supplied for chain validation")

    for idx in range(1, len(attestations)):
        previous = attestations[idx - 1]
        current = attestations[idx]

        expected_previous = {
            "hash": previous.get("digest", {}).get("canonical_sha3_256"),
            "run_id": previous.get("run_id"),
        }
        if current.get("previous") != expected_previous:
            raise ValueError(
                "Broken attestation chain at position {idx}: expected previous {expected} but found {actual}".format(
                    idx=idx,
                    expected=expected_previous,
                    actual=current.get("previous"),
                )
            )


def evaluate_attestation_chain(
    attestations: Sequence[dict[str, Any]], policy: PolicyEngine, *, now: datetime | None = None
) -> PolicyResult:
    """Validate chain continuity then evaluate control policy."""

    validate_chain(attestations)
    evidence = [ControlEvidence.from_attestation(attestation) for attestation in attestations]
    return policy.evaluate(evidence, now=now)
