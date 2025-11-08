"""Canonicalization helpers for Milestone 1 Nmap outputs.

The canonical form is intentionally conservative – it only records the data
required by the milestone specification so verifiers can deterministically
rebuild the projection.  The helper below understands the XML that `nmap`
produces when invoked with ``-oX`` and extracts a tiny, stable JSON
representation describing the state of ports 139 and 445 for every host in the
scan.  The resulting bytes are encoded using ``utf-8`` with sorted keys and
minified separators to remove any incidental whitespace differences between
platforms.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
import json
from typing import Iterable

from lxml import etree


TARGET_PORTS = {"139", "445"}


@dataclass(frozen=True)
class CanonicalPort:
    """Serializable shape describing a single port entry."""

    portid: int
    protocol: str
    state: str
    reason: str | None
    service: dict[str, str]


@dataclass(frozen=True)
class CanonicalHost:
    """Serializable shape describing a single host from an Nmap run."""

    addresses: list[dict[str, str]]
    hostnames: list[str]
    status: str | None
    ports: list[CanonicalPort]


def _normalise_service_attrs(service_element: etree._Element | None) -> dict[str, str]:
    if service_element is None:
        return {}
    attrs = {
        key: service_element.get(key, "")
        for key in sorted(service_element.keys())
        if service_element.get(key)
    }
    return attrs


def _extract_ports(host_element: etree._Element) -> Iterable[CanonicalPort]:
    ports_element = host_element.find("ports")
    if ports_element is None:
        return []

    ports: list[CanonicalPort] = []
    for port in ports_element.findall("port"):
        portid = port.get("portid")
        if portid not in TARGET_PORTS:
            continue

        protocol = port.get("protocol", "")
        state_element = port.find("state")
        state = state_element.get("state") if state_element is not None else "unknown"
        reason = state_element.get("reason") if state_element is not None else None
        service = _normalise_service_attrs(port.find("service"))

        ports.append(
            CanonicalPort(
                portid=int(portid),
                protocol=protocol,
                state=state,
                reason=reason,
                service=service,
            )
        )

    ports.sort(key=lambda entry: entry.portid)
    return ports


def _extract_host(host: etree._Element) -> CanonicalHost | None:
    ports = list(_extract_ports(host))
    if not ports:
        return None

    addresses = [
        {
            "addr": address.get("addr", ""),
            "addrtype": address.get("addrtype", ""),
        }
        for address in host.findall("address")
    ]
    addresses.sort(key=lambda item: (item["addrtype"], item["addr"]))

    hostname_entries = host.findall("hostnames/hostname")
    hostnames = sorted({entry.get("name", "") for entry in hostname_entries if entry.get("name")})

    status_element = host.find("status")
    status = status_element.get("state") if status_element is not None else None

    return CanonicalHost(
        addresses=addresses,
        hostnames=hostnames,
        status=status,
        ports=ports,
    )


def _extract_nmap_metadata(root: etree._Element) -> dict[str, str]:
    attrs = {key: root.get(key, "") for key in sorted(root.keys()) if root.get(key)}
    return attrs


def canon_ports_139_445(xml_bytes: bytes) -> bytes:
    """Produce the canonical JSON projection for an Nmap XML payload.

    Args:
        xml_bytes: Raw XML emitted by Nmap (``-oX``).

    Returns:
        Bytes representing the canonical JSON document.

    Raises:
        ValueError: If the XML cannot be parsed.
    """

    if isinstance(xml_bytes, str):
        xml_bytes = xml_bytes.encode("utf-8")

    try:
        root = etree.fromstring(xml_bytes)
    except etree.XMLSyntaxError as exc:  # pragma: no cover - defensive
        raise ValueError("Unable to parse Nmap XML payload") from exc

    hosts: list[CanonicalHost] = []
    for host in root.findall("host"):
        canonical_host = _extract_host(host)
        if canonical_host is not None:
            hosts.append(canonical_host)

    hosts.sort(
        key=lambda host_entry: (
            host_entry.addresses[0]["addr"] if host_entry.addresses else "",
            host_entry.addresses[0]["addrtype"] if host_entry.addresses else "",
        )
    )

    canonical_payload = {
        "nmaprun": _extract_nmap_metadata(root),
        "hosts": [
            {
                "addresses": host_entry.addresses,
                "hostnames": host_entry.hostnames,
                "status": host_entry.status,
                "ports": [asdict(port) for port in host_entry.ports],
            }
            for host_entry in hosts
        ],
    }

    return json.dumps(canonical_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
