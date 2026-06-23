"""Canonical input helpers for configurable ZK policy proofs."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class PortExposurePolicy:
    """Policy that fails when forbidden ports are exposed as open."""

    policy_id: str
    forbidden_ports: tuple[int, ...]
    description: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PortExposurePolicy":
        policy_id = data.get("id")
        if not isinstance(policy_id, str) or not policy_id:
            raise ValueError("Policy definition must include a non-empty string id")

        policy_type = data.get("type", "forbidden_open_ports")
        if policy_type != "forbidden_open_ports":
            raise ValueError(f"Unsupported policy type: {policy_type}")

        raw_ports = data.get("forbidden_ports")
        if not isinstance(raw_ports, list) or not raw_ports:
            raise ValueError("Policy definition must include one or more forbidden_ports")

        ports = _normalize_ports(raw_ports)
        description = data.get("description")
        if not isinstance(description, str) or not description:
            description = f"No forbidden ports exposed: {', '.join(str(port) for port in ports)}"

        return cls(policy_id=policy_id, forbidden_ports=ports, description=description)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.policy_id,
            "type": "forbidden_open_ports",
            "forbidden_ports": list(self.forbidden_ports),
            "description": self.description,
        }


DEFAULT_POLICY = PortExposurePolicy(
    policy_id="no_smb_exposed",
    forbidden_ports=(139, 445),
    description="SMB ports 139 and 445 must not be open",
)


def _normalize_ports(values: Iterable[Any]) -> tuple[int, ...]:
    ports: list[int] = []
    for value in values:
        if isinstance(value, bool):
            raise ValueError("Port values must be integers between 1 and 65535")
        try:
            port = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("Port values must be integers between 1 and 65535") from exc
        if port < 1 or port > 65535:
            raise ValueError("Port values must be integers between 1 and 65535")
        ports.append(port)
    return tuple(sorted(set(ports)))


def evaluate_port_exposure_policy(
    canonical_document: dict[str, Any], policy: PortExposurePolicy
) -> bool:
    """Return whether the canonical Nmap projection satisfies the policy."""

    forbidden = set(policy.forbidden_ports)
    for host in canonical_document.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("portid") in forbidden and port.get("state") == "open":
                return False
    return True


def build_policy_input(
    canonical_bytes: bytes, policy: PortExposurePolicy | str
) -> dict[str, Any]:
    """Return the canonical policy input structure used by the zkVM program."""

    resolved_policy = DEFAULT_POLICY if isinstance(policy, str) else policy
    return {
        "policy": resolved_policy.to_dict(),
        "result_commitment": {
            "algorithm": "SHA3-256",
            "digest_hex": hashlib.sha3_256(canonical_bytes).hexdigest(),
        },
    }


def input_commitment_hex(policy_input: dict[str, Any]) -> str:
    """Derive the commitment that binds the proof to the canonical input."""

    return policy_input["result_commitment"]["digest_hex"]
