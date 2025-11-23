"""Append-only chain log abstractions and verification utilities."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Protocol

from ..agent.pqc_sign import sign_dilithium2, verify_dilithium2


class ChainLog(Protocol):
    """Append-only log interface for chained records."""

    def append(self, record: "SignedRecord") -> None:  # pragma: no cover - interface
        ...

    def __iter__(self) -> Iterator["SignedRecord"]:  # pragma: no cover - interface
        ...


@dataclass(slots=True)
class SignedRecord:
    """Envelope for an append-only chain entry."""

    sequence: int
    previous_hash: str | None
    payload: bytes
    signature: str

    @classmethod
    def create(
        cls, sequence: int, previous_hash: str | None, payload: bytes, private_key: bytes
    ) -> "SignedRecord":
        canonical_bytes = cls._canonical_bytes(sequence, previous_hash, payload)
        signature = sign_dilithium2(private_key, canonical_bytes)
        return cls(sequence, previous_hash, payload, signature)

    @staticmethod
    def _canonical_bytes(sequence: int, previous_hash: str | None, payload: bytes) -> bytes:
        payload_b64 = base64.b64encode(payload).decode("ascii")
        record_hash = hashlib.sha3_256((previous_hash or "").encode("utf-8") + payload).hexdigest()
        canonical = {
            "sequence": sequence,
            "previous_hash": previous_hash,
            "payload_b64": payload_b64,
            "record_hash": record_hash,
        }
        return json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def verify_signature(self, public_key: bytes) -> bool:
        return verify_dilithium2(public_key, self._canonical_bytes(self.sequence, self.previous_hash, self.payload), self.signature)

    def record_hash(self) -> str:
        return hashlib.sha3_256((self.previous_hash or "").encode("utf-8") + self.payload).hexdigest()

    def to_dict(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "previous_hash": self.previous_hash,
            "payload_b64": base64.b64encode(self.payload).decode("ascii"),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "SignedRecord":
        payload_b64 = data.get("payload_b64")
        if not isinstance(payload_b64, str):
            raise ValueError("Invalid payload encoding")
        payload = base64.b64decode(payload_b64.encode("ascii"))
        return cls(
            sequence=int(data["sequence"]),
            previous_hash=data.get("previous_hash"),
            payload=payload,
            signature=str(data["signature"]),
        )


class FileChainLog:
    """File-backed append-only log using JSON lines."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def append(self, record: SignedRecord) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_dict()) + "\n")

    def __iter__(self) -> Iterator[SignedRecord]:
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                yield SignedRecord.from_dict(json.loads(line))


class MemoryChainLog:
    """In-memory log useful for testing."""

    def __init__(self) -> None:
        self._records: list[SignedRecord] = []

    def append(self, record: SignedRecord) -> None:
        self._records.append(record)

    def __iter__(self) -> Iterator[SignedRecord]:
        return iter(self._records)


def verify_chain(log: ChainLog, public_key: bytes) -> list[SignedRecord]:
    """Replay a chain log verifying sequence, hash continuity, and signatures."""

    verified: list[SignedRecord] = []
    expected_sequence = 0
    previous_hash: str | None = None

    for record in log:
        if record.sequence != expected_sequence:
            raise ValueError(f"Unexpected sequence number: {record.sequence}, expected {expected_sequence}")
        if record.previous_hash != previous_hash:
            raise ValueError("Hash chain continuity violation")
        if not record.verify_signature(public_key):
            raise ValueError("Signature verification failed")

        computed_hash = record.record_hash()
        previous_hash = computed_hash
        expected_sequence += 1
        verified.append(record)

    return verified
