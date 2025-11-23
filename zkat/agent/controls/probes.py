from __future__ import annotations

from .base import ControlContext, ControlMetadata, ControlProbe, ControlResult, Evidence


class PlaceholderProbe(ControlProbe):
    control_id = "placeholder.baseline"
    metadata = ControlMetadata(source="zkat.agent", version="1.0.0", trust_domain="local")

    def collect(self) -> ControlResult:
        evidence = Evidence(
            kind="placeholder", 
            summary="Baseline placeholder control",
            data={"run_id": self.context.run_id},
        )
        return ControlResult(self.control_id, self.metadata, [evidence])


class NmapCanonicalProbe(ControlProbe):
    control_id = "network.nmap.canonical"
    metadata = ControlMetadata(source="nmap", version="7.x", trust_domain="local")

    def collect(self) -> ControlResult:
        evidence = Evidence(
            kind="network-scan",
            summary="Canonicalized Nmap evidence",
            data={
                "digest": self.context.digest,
                "hosts": self.context.canonical.get("hosts", []),
                "source": self.context.nmap,
            },
        )
        return ControlResult(self.control_id, self.metadata, [evidence])


class SysdigProbe(ControlProbe):
    control_id = "runtime.sysdig"
    metadata = ControlMetadata(source="sysdig", version="0.0.0-stub", trust_domain="sysdig")

    def collect(self) -> ControlResult:
        evidence = Evidence(
            kind="sysdig-snapshot",
            summary="Sysdig control (stub)",
            data={"status": "not-collected", "reason": "stub"},
        )
        return ControlResult(self.control_id, self.metadata, [evidence], status="pending")


class OSQueryProbe(ControlProbe):
    control_id = "runtime.osquery"
    metadata = ControlMetadata(source="osquery", version="0.0.0-stub", trust_domain="osquery")

    def collect(self) -> ControlResult:
        evidence = Evidence(
            kind="osquery-snapshot",
            summary="OSQuery control (stub)",
            data={"status": "not-collected", "reason": "stub"},
        )
        return ControlResult(self.control_id, self.metadata, [evidence], status="pending")


class CloudPostureProbe(ControlProbe):
    control_id = "cloud.posture"
    metadata = ControlMetadata(source="cloud-posture", version="0.0.0-stub", trust_domain="cloud")

    def collect(self) -> ControlResult:
        evidence = Evidence(
            kind="posture-report",
            summary="Cloud posture control (stub)",
            data={"status": "not-collected", "reason": "stub"},
        )
        return ControlResult(self.control_id, self.metadata, [evidence], status="pending")
