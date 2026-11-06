"""BSGS bounded-interval ECDLP (educational).

Every recovery is cross-checked against an INDEPENDENT reference: a from-scratch
brute-force scan over the interval, and the structurally different kangaroo
solver on the same instances. Never self-consistency alone.
"""

from __future__ import annotations

import random

import pytest

from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.research.ecdlp.bsgs import baby_step_giant_step, recover_via_bsgs
from keylab.research.ecdlp.kangaroo import pollard_kangaroo


def _bruteforce(point, lo, hi):
    """Independent reference: linear scan, no BSGS logic involved."""
    for k in range(lo, hi + 1):
        if scalar_mult(k, G) == point:
            return k
    return None


def test_bsgs_matches_bruteforce_reference() -> None:
    rng = random.Random(11)
    for _ in range(12):
        lo = rng.randrange(0, 5_000)
        hi = lo + rng.randrange(1, 3_000)
        k = rng.randrange(lo, hi + 1)
        got = baby_step_giant_step(scalar_mult(k, G), lo, hi)
        assert got == _bruteforce(scalar_mult(k, G), lo, hi) == k


def test_bsgs_agrees_with_kangaroo() -> None:
    # Two structurally different algorithms must agree on the same instances.
    rng = random.Random(5)
    for _ in range(6):
        lo = rng.randrange(1, 10_000)
        hi = lo + rng.randrange(1, 4_096)
        k = rng.randrange(lo, hi + 1)
        q = scalar_mult(k, G)
        assert baby_step_giant_step(q, lo, hi) == pollard_kangaroo(q, lo, hi) == k


def test_bsgs_endpoints_and_width_zero() -> None:
    lo, hi = 1000, 1000 + 4096
    for k in (lo, hi, (lo + hi) // 2):
        assert baby_step_giant_step(scalar_mult(k, G), lo, hi) == k
    assert baby_step_giant_step(scalar_mult(777, G), 777, 777) == 777
    assert baby_step_giant_step(scalar_mult(778, G), 777, 777) is None  # not in singleton


def test_bsgs_returns_none_when_out_of_interval() -> None:
    k = 50_000
    assert baby_step_giant_step(scalar_mult(k, G), 1, 2048) is None


def test_bsgs_forward_verified() -> None:
    k = 0xC0FFEE
    got = baby_step_giant_step(scalar_mult(k, G), k - 3000, k + 3000)
    assert got is not None and scalar_mult(got, G) == scalar_mult(k, G)


@pytest.mark.parametrize("lo,hi", [(-1, 10), (10, 5), (0, N)])
def test_bsgs_rejects_bad_intervals(lo, hi) -> None:
    with pytest.raises((ValueError, TypeError)):
        baby_step_giant_step(scalar_mult(7, G), lo, hi)


def test_bsgs_rejects_non_integer_bounds() -> None:
    with pytest.raises(TypeError):
        baby_step_giant_step(scalar_mult(7, G), 1.0, 10)  # type: ignore[arg-type]


def test_recover_via_bsgs_report() -> None:
    k = 88_888
    report = recover_via_bsgs(scalar_mult(k, G), k - 2000, k + 2000)
    assert report["found"] and report["k"] == k
    assert report["method"] == "baby-step-giant-step" and report["width"] == 4000
