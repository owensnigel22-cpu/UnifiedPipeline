"""Pollard's kangaroo for the bounded-interval ECDLP (educational recovery)."""

from __future__ import annotations

import random

import pytest

from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.recovery.kangaroo import pollard_kangaroo, recover_via_kangaroo


def test_kangaroo_recovers_k_in_small_intervals() -> None:
    rng = random.Random(7)
    for _ in range(8):
        lo = rng.randrange(1, 10_000)
        hi = lo + rng.randrange(1, 4096)
        k = rng.randrange(lo, hi + 1)
        got = pollard_kangaroo(scalar_mult(k, G), lo, hi)
        assert got == k, f"k={k} interval=[{lo},{hi}] got={got}"


def test_kangaroo_recovers_at_interval_endpoints() -> None:
    lo, hi = 1000, 1000 + 2048
    for k in (lo, hi, (lo + hi) // 2):
        assert pollard_kangaroo(scalar_mult(k, G), lo, hi) == k


def test_kangaroo_width_zero_interval() -> None:
    k = 12345
    assert pollard_kangaroo(scalar_mult(k, G), k, k) == k
    assert pollard_kangaroo(scalar_mult(k + 1, G), k, k) is None  # Q not in the singleton interval


def test_kangaroo_result_is_forward_verified() -> None:
    k = 0xC0FFEE
    lo, hi = k - 2000, k + 2000
    got = pollard_kangaroo(scalar_mult(k, G), lo, hi)
    assert got is not None and scalar_mult(got, G) == scalar_mult(k, G)


def test_kangaroo_returns_none_when_out_of_interval() -> None:
    # k is outside [lo, hi]; no collision should validate.
    k = 50_000
    assert pollard_kangaroo(scalar_mult(k, G), 1, 2048, max_steps=5000) is None


@pytest.mark.parametrize("lo,hi", [(-1, 10), (10, 5), (0, N)])
def test_kangaroo_rejects_bad_intervals(lo, hi) -> None:
    with pytest.raises((ValueError, TypeError)):
        pollard_kangaroo(scalar_mult(7, G), lo, hi)


def test_kangaroo_rejects_non_integer_bounds() -> None:
    with pytest.raises(TypeError):
        pollard_kangaroo(scalar_mult(7, G), 1.0, 10)  # type: ignore[arg-type]


def test_recover_via_kangaroo_report() -> None:
    k = 77_777
    report = recover_via_kangaroo(scalar_mult(k, G), k - 3000, k + 3000)
    assert report["found"] and report["k"] == k
    assert report["method"] == "pollard-kangaroo"
    assert report["width"] == 6000
