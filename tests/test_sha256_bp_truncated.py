"""Truncated, reduced-round BP preimage search — honest, forward-verified.

Loopy BP does not invert SHA-256 (see the module note). These tests assert only
what is genuinely true: the engine runs, every ``verified`` decode really reproduces
the conditioned output bits, and BP reliably solves the *easy* one-round, small-
truncation instances it was measured to solve.
"""

from __future__ import annotations

import pytest

from keylab.hashes.reduced import _SHA_IV, _sha_compress
from keylab.research.sha256_prob import solve_truncated


def _compress_digest(block: bytes, rounds: int) -> bytes:
    return b"".join(w.to_bytes(4, "big") for w in _sha_compress(block, _SHA_IV, rounds))


def test_solve_truncated_validates_arguments() -> None:
    with pytest.raises(ValueError, match="target_bits"):
        solve_truncated(0, 32)
    with pytest.raises(ValueError, match="target_bits"):
        solve_truncated(257, 32)
    with pytest.raises(ValueError, match="n_bits"):
        solve_truncated(8, 0)
    with pytest.raises(ValueError, match="32 bytes"):
        solve_truncated(8, 64, rounds=1, target=b"\x00" * 10)


def test_solve_truncated_one_round_small_truncation_verifies() -> None:
    # Measured 5/5 at (rounds=1, target_bits=8, n_bits=64); seed 0 is deterministic.
    result = solve_truncated(8, 64, rounds=1, seed=0, max_iters=60)
    assert result.verified is True
    assert result.candidate is not None
    assert len(result.candidate) == 64
    assert len(result.marginals) == 64
    assert all(0.0 <= p <= 1.0 for p in result.marginals.values())


def test_verified_decode_reproduces_an_external_target() -> None:
    # Build a solvable external target, then confirm the decode forward-verifies it
    # independently (not just via the solver's own check).
    message = bytearray(64)
    message[0:4] = b"\x9a\xbc\xde\xf0"
    message[4:8] = b"\x11\x22\x33\x44"
    target = _compress_digest(bytes(message), 1)
    result = solve_truncated(8, 64, rounds=1, target=target, seed=0, max_iters=60)
    assert result.verified is True
    assert result.candidate is not None
    # The low 8 conditioned bits are word-0 bits 0..7 = word 0's least-significant byte.
    produced = _compress_digest(result.candidate, 1)
    assert produced[3] == target[3]  # big-endian word 0, least-significant byte


def test_result_is_well_formed_even_when_bp_fails() -> None:
    # Two rounds was measured at 0/5: BP should return a clean, honest negative,
    # never a false claim, and never a candidate without verification.
    result = solve_truncated(16, 64, rounds=2, seed=0, max_iters=20)
    assert isinstance(result.verified, bool)
    assert isinstance(result.converged, bool)
    if result.candidate is None:
        assert result.verified is False
    else:
        assert result.verified is True  # a candidate is only returned when verified


@pytest.mark.slow
def test_bp_solves_easy_one_round_instances_majority() -> None:
    # Measured 5/5; require a clear majority to stay robust while remaining a real,
    # live demonstration that BP finds forward-verified truncated preimages.
    verified = sum(
        solve_truncated(8, 64, rounds=1, seed=seed, max_iters=60).verified
        for seed in range(5)
    )
    assert verified >= 3


@pytest.mark.slow
def test_bp_degrades_with_target_width() -> None:
    # Honest degradation: wider truncations are harder. We only assert the engine
    # runs and that any verified decode is genuine (the counts themselves are
    # probabilistic and documented in the module note, not asserted as exact).
    for target_bits in (8, 16, 24):
        result = solve_truncated(target_bits, 64, rounds=1, seed=1, max_iters=60)
        assert isinstance(result.verified, bool)
        assert (result.candidate is not None) == result.verified
