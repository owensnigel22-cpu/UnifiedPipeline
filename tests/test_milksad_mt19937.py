"""Tests for the faithful MT19937 and Milk Sad timestamp-seed demo."""

from __future__ import annotations

import pytest

from keylab.research.weak_rng_milksad import (
    MT19937,
    MilksadHit,
    milksad_entropy,
    milksad_hash160,
    milksad_key_from_timestamp,
    scan_timestamp_range,
)

# C++ standard [rand.req.predef]: a default-constructed std::mt19937 (seed 5489),
# invoked 10,000 times, produces 4123659995 as its 10,000th output.
_STD_MT19937_10000TH = 4123659995


def test_mt19937_matches_cpp_standard_vector() -> None:
    rng = MT19937()  # default seed 5489
    value = 0
    for _ in range(10_000):
        value = rng.next_uint32()
    assert value == _STD_MT19937_10000TH


def test_mt19937_outputs_are_32_bit() -> None:
    rng = MT19937(12345)
    for _ in range(2_000):
        value = rng.next_uint32()
        assert 0 <= value <= 0xFFFFFFFF


def test_mt19937_is_deterministic_per_seed() -> None:
    first = [MT19937(7).next_uint32() for _ in range(50)]
    second = [MT19937(7).next_uint32() for _ in range(50)]
    assert first == second
    assert [MT19937(8).next_uint32() for _ in range(50)] != first


def test_mt19937_negative_seed_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        MT19937(-1)


def test_milksad_entropy_deterministic_and_sized() -> None:
    entropy = milksad_entropy(1_690_000_000, 32)
    assert isinstance(entropy, bytes)
    assert len(entropy) == 32
    assert milksad_entropy(1_690_000_000, 32) == entropy
    assert milksad_entropy(1_690_000_001, 32) != entropy
    assert all(0 <= byte <= 255 for byte in entropy)


def test_milksad_entropy_length_validated() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        milksad_entropy(1, 0)


def test_scan_recovers_planted_timestamp() -> None:
    planted = 1_690_000_123
    target = milksad_hash160(planted)
    hits = scan_timestamp_range(1_690_000_100, 1_690_000_150, [target])
    assert len(hits) == 1
    hit = hits[0]
    assert isinstance(hit, MilksadHit)
    assert hit.timestamp == planted
    assert hit.hash160 == target
    # The recovered scalar must forward-derive the same key that was planted.
    assert hit.private_key == milksad_key_from_timestamp(planted)


def test_scan_masks_private_key_by_default() -> None:
    planted = 1_690_000_200
    target = milksad_hash160(planted)
    hit = scan_timestamp_range(1_690_000_200, 1_690_000_201, [target])[0]
    masked = hit.to_dict()
    assert masked["private_key"] == "<redacted>"
    revealed = hit.to_dict(reveal_private=True)
    assert revealed["private_key"] == format(hit.private_key, "064x")


def test_scan_no_match_returns_empty() -> None:
    bogus = bytes(20)
    assert scan_timestamp_range(1_000, 1_050, [bogus]) == []


def test_scan_validates_arguments() -> None:
    target = milksad_hash160(42)
    with pytest.raises(ValueError, match="start_seed"):
        scan_timestamp_range(-1, 10, [target])
    with pytest.raises(ValueError, match="end_seed"):
        scan_timestamp_range(10, 5, [target])
    with pytest.raises(ValueError, match="20-byte HASH160"):
        scan_timestamp_range(0, 10, [b"too-short"])
    with pytest.raises(ValueError, match="at least one target"):
        scan_timestamp_range(0, 10, [])
