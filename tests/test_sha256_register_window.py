"""Deterministic register-window reduced-round compression preimages (8..16 rounds)."""

from __future__ import annotations

import hashlib

import pytest

from keylab.research.sha256_reduced import (
    reduced_compress,
    register_window_preimage,
)


@pytest.mark.parametrize("rounds", range(8, 17))
@pytest.mark.parametrize("seed", range(4))
def test_preimage_forward_verifies(rounds: int, seed: int) -> None:
    target = hashlib.sha256(f"{rounds}:{seed}".encode()).digest()
    result = register_window_preimage(target, rounds=rounds, free_fill=(seed * 0x9E3779B1) & 0xFFFFFFFF)
    assert result.verified
    assert len(result.block) == 64
    assert reduced_compress(result.block, rounds) == target


def test_distinct_free_fill_gives_distinct_valid_preimages() -> None:
    target = hashlib.sha256(b"distinct").digest()
    a = register_window_preimage(target, rounds=14, free_fill=0)
    b = register_window_preimage(target, rounds=14, free_fill=0x1234_5678)
    assert a.block != b.block
    assert reduced_compress(a.block, 14) == target
    assert reduced_compress(b.block, 14) == target


@pytest.mark.parametrize("rounds", [7, 17, 0, 64])
def test_rounds_out_of_supported_range(rounds: int) -> None:
    with pytest.raises(ValueError, match="rounds"):
        register_window_preimage(b"\x00" * 32, rounds=rounds)


def test_target_length_validated() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        register_window_preimage(b"\x00" * 31, rounds=10)


def test_free_fill_range_validated() -> None:
    with pytest.raises(ValueError, match="free_fill"):
        register_window_preimage(b"\x00" * 32, rounds=10, free_fill=1 << 32)


def test_reduced_compress_block_size_validated() -> None:
    with pytest.raises(ValueError, match="64 bytes"):
        reduced_compress(b"\x00" * 63, 10)


def test_custom_initial_state_round_trips() -> None:
    target = hashlib.sha256(b"iv").digest()
    initial = hashlib.sha256(b"custom-iv").digest()
    result = register_window_preimage(target, rounds=12, initial_state=initial)
    assert reduced_compress(result.block, 12, initial_state=initial) == target
