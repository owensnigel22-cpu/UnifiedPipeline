"""Weak-RNG incremental range scan: correct, bounded, forward-verified."""

from __future__ import annotations

import pytest

from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.research.weak_rng import incremental_pubkey_scan, pubkey_sec


def test_scan_finds_key_in_window_and_verifies() -> None:
    key = 1_000_123
    result = incremental_pubkey_scan(pubkey_sec(key), 1_000_000, 500)
    assert result.found is True
    assert result.private_key == key
    assert result.verified is True
    assert result.scanned == key - 1_000_000 + 1


def test_scan_finds_key_at_window_start() -> None:
    key = 777
    result = incremental_pubkey_scan(pubkey_sec(key), key, 1)
    assert result.found is True
    assert result.private_key == key
    assert result.scanned == 1


def test_scan_reports_clean_miss() -> None:
    target = pubkey_sec(5_000_000)
    result = incremental_pubkey_scan(target, 1_000_000, 100)
    assert result.found is False
    assert result.private_key is None
    assert result.verified is False
    assert result.scanned == 100


def test_scan_accepts_uncompressed_and_point_targets() -> None:
    key = 424_242
    assert incremental_pubkey_scan(pubkey_sec(key, compressed=False), key - 10, 20).private_key == key
    point = scalar_mult(key, G)
    assert incremental_pubkey_scan(point, key - 10, 20).private_key == key


def test_scan_validates_arguments() -> None:
    target = pubkey_sec(10)
    with pytest.raises(ValueError, match="start"):
        incremental_pubkey_scan(target, -1, 10)
    with pytest.raises(ValueError, match="count"):
        incremental_pubkey_scan(target, 0, 0)
    with pytest.raises(ValueError, match="group order"):
        incremental_pubkey_scan(target, N - 1, 5)


def test_scan_rejects_bad_target_type() -> None:
    with pytest.raises(TypeError):
        incremental_pubkey_scan(12345, 0, 1)  # type: ignore[arg-type]


def test_pubkey_sec_validates_range() -> None:
    with pytest.raises(ValueError, match="private_key"):
        pubkey_sec(0)
    with pytest.raises(ValueError, match="private_key"):
        pubkey_sec(N)
