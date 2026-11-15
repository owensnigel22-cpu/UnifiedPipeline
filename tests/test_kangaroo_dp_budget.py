"""Phase D: the RAM-bounded distinguished-point sizing knob (max_table_entries)."""

from __future__ import annotations

import random

import pytest

from keylab.ec.secp256k1 import G, scalar_mult
from keylab.research.ecdlp.kangaroo import (
    _default_dp_bits,
    _dp_bits_for_budget,
    _expected_tame_hops,
    pollard_kangaroo,
)


def test_dp_bits_for_budget_never_below_reliability_floor() -> None:
    # A generous budget must not drop dp_bits below the width-based default.
    for width in (2**16, 2**24, 2**32):
        floor = _default_dp_bits(width)
        assert _dp_bits_for_budget(width, max_table_entries=10**9) == floor


def test_dp_bits_for_budget_tighter_budget_raises_dp_bits() -> None:
    width = 2**32
    floor = _default_dp_bits(width)
    tight = _dp_bits_for_budget(width, max_table_entries=1)
    assert tight >= floor
    # Forcing a single-entry table must make distinguished points at least as rare.
    assert tight > floor


def test_dp_bits_for_budget_keeps_expected_table_under_budget() -> None:
    width = 2**32
    budget = 4
    bits = _dp_bits_for_budget(width, max_table_entries=budget)
    expected_entries = _expected_tame_hops(width) / (2**bits)
    assert expected_entries <= budget


def test_dp_bits_for_budget_rejects_nonpositive() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        _dp_bits_for_budget(2**16, max_table_entries=0)


def test_kangaroo_solves_with_table_budget() -> None:
    rng = random.Random(11)
    for _ in range(5):
        lo = rng.randrange(1, 10_000)
        hi = lo + rng.randrange(1, 4096)
        k = rng.randrange(lo, hi + 1)
        got = pollard_kangaroo(scalar_mult(k, G), lo, hi, max_table_entries=4)
        assert got == k, f"k={k} interval=[{lo},{hi}] got={got}"


def test_kangaroo_rejects_dp_bits_and_budget_together() -> None:
    with pytest.raises(ValueError, match="not both"):
        pollard_kangaroo(scalar_mult(7, G), 1, 2048, dp_bits=8, max_table_entries=4)


def test_kangaroo_rejects_nonpositive_budget() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        pollard_kangaroo(scalar_mult(7, G), 1, 2048, max_table_entries=0)
