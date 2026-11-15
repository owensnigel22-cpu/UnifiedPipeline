"""Phase B: Bloom filter correctness and multi-target brainwallet cracking."""

from __future__ import annotations

import random

import pytest

from keylab.research.brainwallet import (
    BrainwalletHit,
    crack_brainwallet_multi,
    passphrase_hash160s,
    passphrase_to_privkey,
)
from keylab.research.forensics.bloom import BloomFilter

_KNOWN = b"correct horse battery staple"
_DECOYS = [b"password", b"123456", b"letmein", b"satoshi", b"hunter2"]


def test_bloom_has_no_false_negatives() -> None:
    rng = random.Random(1)
    items = [rng.randbytes(20) for _ in range(500)]
    bloom = BloomFilter.from_items(items, error_rate=0.01)
    assert len(bloom) == 500
    for item in items:
        assert item in bloom  # every added item must test positive


def test_bloom_false_positive_rate_is_bounded() -> None:
    rng = random.Random(2)
    members = {rng.randbytes(20) for _ in range(1000)}
    bloom = BloomFilter.from_items(members, error_rate=0.01)

    trials = 10_000
    false_positives = 0
    for _ in range(trials):
        candidate = rng.randbytes(20)
        if candidate in members:
            continue
        if candidate in bloom:
            false_positives += 1
    # Theoretical ~1%; assert comfortably below 5% to stay deterministic-but-robust.
    assert false_positives / trials < 0.05


def test_bloom_rejects_bad_parameters() -> None:
    with pytest.raises(ValueError, match="capacity"):
        BloomFilter(0)
    with pytest.raises(ValueError, match="error_rate"):
        BloomFilter(10, error_rate=0.0)
    with pytest.raises(ValueError, match="error_rate"):
        BloomFilter(10, error_rate=1.0)


def _target_for(passphrase: bytes) -> bytes:
    return passphrase_hash160s(passphrase)["compressed"]


@pytest.mark.parametrize("executor", ["serial", "thread"])
def test_crack_multi_finds_planted_passphrase(executor: str) -> None:
    target = _target_for(_KNOWN)
    wordlist = [*_DECOYS, _KNOWN, b"more decoys"]

    hits = crack_brainwallet_multi(
        wordlist, [target], executor=executor, chunk_size=2, reveal_private_key=True
    )

    assert len(hits) == 1
    hit = hits[0]
    assert isinstance(hit, BrainwalletHit)
    assert hit.passphrase == _KNOWN
    assert hit.matched_form == "compressed"
    assert hit.target_hash160 == target
    assert hit.private_key_hex == f"{passphrase_to_privkey(_KNOWN):064x}"


def test_crack_multi_masks_private_key_by_default() -> None:
    target = _target_for(_KNOWN)
    hits = crack_brainwallet_multi([_KNOWN], [target])
    assert len(hits) == 1
    assert hits[0].private_key_hex is None


def test_crack_multi_reports_no_hits_when_absent() -> None:
    target = _target_for(_KNOWN)
    assert crack_brainwallet_multi(_DECOYS, [target]) == []


def test_crack_multi_validates_arguments() -> None:
    target = _target_for(_KNOWN)
    with pytest.raises(ValueError, match="executor"):
        crack_brainwallet_multi([_KNOWN], [target], executor="gpu")
    with pytest.raises(ValueError, match="chunk_size"):
        crack_brainwallet_multi([_KNOWN], [target], chunk_size=0)
    with pytest.raises(ValueError, match="20-byte HASH160"):
        crack_brainwallet_multi([_KNOWN], [b"too short"])
    assert crack_brainwallet_multi([_KNOWN], []) == []


def test_crack_multi_finds_multiple_distinct_targets() -> None:
    known2 = b"another weak passphrase"
    targets = [_target_for(_KNOWN), _target_for(known2)]
    wordlist = [*_DECOYS, _KNOWN, known2]
    hits = crack_brainwallet_multi(wordlist, targets, chunk_size=3)
    assert {hit.passphrase for hit in hits} == {_KNOWN, known2}


@pytest.mark.slow
def test_crack_multi_process_executor_matches_serial() -> None:
    # Process pool parity (slow on Windows due to spawn overhead).
    target = _target_for(_KNOWN)
    wordlist = [*_DECOYS, _KNOWN, *_DECOYS]
    serial = crack_brainwallet_multi(wordlist, [target], executor="serial")
    parallel = crack_brainwallet_multi(wordlist, [target], executor="process", workers=2, chunk_size=2)
    assert {hit.passphrase for hit in parallel} == {hit.passphrase for hit in serial} == {_KNOWN}
