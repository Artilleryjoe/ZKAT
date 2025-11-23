from __future__ import annotations

from datetime import datetime

from zkat.agent.controls import (
    ControlContext,
    ControlMetadata,
    ControlProbe,
    discover_control_probes,
    run_control_probes,
)
from zkat.agent.controls.base import ControlResult


SAMPLE_CONTEXT = ControlContext(
    run_id="20240101T000000Z",
    digest="0" * 64,
    canonical={"hosts": []},
    nmap={"source": "file"},
)


def test_discovery_registers_builtin_probes():
    control_ids = [probe.control_id for probe in discover_control_probes()]
    assert control_ids[:2] == ["placeholder.baseline", "network.nmap.canonical"]
    assert {"runtime.sysdig", "runtime.osquery", "cloud.posture"}.issubset(
        set(control_ids)
    )


def test_run_control_probes_emits_schema_compliant_results():
    results = run_control_probes(SAMPLE_CONTEXT)
    assert results, "Expected at least one control result"
    for result in results:
        payload = result.to_dict()
        assert payload["control_id"]
        assert set(payload["metadata"]).issuperset({"source", "version", "trust_domain"})
        datetime.fromisoformat(payload["collected_at"].replace("Z", "+00:00"))
        assert isinstance(payload["evidence"], list)
        for evidence in payload["evidence"]:
            assert set(evidence) == {"kind", "summary", "data"}


def test_run_control_probes_preserves_explicit_order(monkeypatch):
    monkeypatch.setattr(ControlProbe, "_registry", {})

    class FirstProbe(ControlProbe):
        control_id = "first"
        metadata = ControlMetadata(source="first", version="1", trust_domain="t")

        def collect(self) -> ControlResult:
            return ControlResult(self.control_id, self.metadata, [])

    class SecondProbe(ControlProbe):
        control_id = "second"
        metadata = ControlMetadata(source="second", version="1", trust_domain="t")

        def collect(self) -> ControlResult:
            return ControlResult(self.control_id, self.metadata, [])

    results = run_control_probes(SAMPLE_CONTEXT, probes=[FirstProbe, SecondProbe])
    assert [result.control_id for result in results] == ["first", "second"]
