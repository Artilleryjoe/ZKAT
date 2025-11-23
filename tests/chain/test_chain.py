import pytest

from zkat.agent.pqc_sign import derive_public_key
from zkat.chain import MemoryChainLog, SignedRecord, verify_chain


@pytest.fixture
def key_pair():
    private_key = b"test-key"
    public_key = derive_public_key(private_key)
    return private_key, public_key


def test_happy_path_verification(key_pair):
    private_key, public_key = key_pair
    log = MemoryChainLog()

    previous_hash = None
    for sequence in range(3):
        payload = f"payload-{sequence}".encode()
        record = SignedRecord.create(sequence, previous_hash, payload, private_key)
        previous_hash = record.record_hash()
        log.append(record)

    verified = verify_chain(log, public_key)
    assert len(verified) == 3


def test_tampering_detected(key_pair):
    private_key, public_key = key_pair
    log = MemoryChainLog()

    genesis = SignedRecord.create(0, None, b"ok", private_key)
    log.append(genesis)

    tampered_payload = b"evil"
    tampered = SignedRecord(1, genesis.record_hash(), tampered_payload, genesis.signature)
    log.append(tampered)

    with pytest.raises(ValueError):
        verify_chain(log, public_key)


def test_sequence_gap_rejected(key_pair):
    private_key, public_key = key_pair
    log = MemoryChainLog()

    first = SignedRecord.create(0, None, b"first", private_key)
    log.append(first)

    gap_record = SignedRecord.create(2, first.record_hash(), b"third", private_key)
    log.append(gap_record)

    with pytest.raises(ValueError):
        verify_chain(log, public_key)
