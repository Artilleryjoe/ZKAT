from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar, Iterable, Type


@dataclass(frozen=True)
class ControlMetadata:
    """Static metadata about a control probe."""

    source: str
    version: str
    trust_domain: str


@dataclass
class Evidence:
    """Structured evidence emitted by a control probe."""

    kind: str
    summary: str
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "summary": self.summary,
            "data": self.data,
        }


@dataclass
class ControlResult:
    """Result returned by executing a control probe."""

    control_id: str
    metadata: ControlMetadata
    evidence: list[Evidence]
    status: str = "ok"
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "metadata": {
                "source": self.metadata.source,
                "version": self.metadata.version,
                "trust_domain": self.metadata.trust_domain,
            },
            "status": self.status,
            "collected_at": self.collected_at,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass(frozen=True)
class ControlContext:
    """Execution context shared across control probes in a run."""

    run_id: str
    digest: str
    canonical: dict[str, Any]
    nmap: dict[str, Any]


class ControlProbe:
    """Base class for control probes.

    Subclasses must define ``control_id`` and ``metadata`` attributes and
    implement :meth:`collect` to return a :class:`ControlResult`.
    """

    control_id: ClassVar[str]
    metadata: ClassVar[ControlMetadata]
    _registry: ClassVar[dict[str, Type["ControlProbe"]]] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        control_id = getattr(cls, "control_id", None)
        metadata = getattr(cls, "metadata", None)
        if control_id is None or metadata is None:
            return
        if control_id in cls._registry:
            raise ValueError(f"Duplicate control_id registered: {control_id}")
        cls._registry[control_id] = cls

    def __init__(self, context: ControlContext):
        self.context = context

    def collect(self) -> ControlResult:  # pragma: no cover - abstract method
        raise NotImplementedError


def discover_control_probes() -> list[Type[ControlProbe]]:
    """Return registered control probe classes in definition order."""

    return list(ControlProbe._registry.values())


def run_control_probes(context: ControlContext, probes: Iterable[Type[ControlProbe]] | None = None) -> list[ControlResult]:
    """Execute registered probes sequentially and return their results."""

    probe_types: Iterable[Type[ControlProbe]] = probes or discover_control_probes()
    results: list[ControlResult] = []
    for probe_type in probe_types:
        probe = probe_type(context)
        results.append(probe.collect())
    return results
