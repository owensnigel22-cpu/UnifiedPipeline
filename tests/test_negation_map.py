"""Negation-map symmetric kangaroo (educational).

Correctness is cross-checked against BSGS (a structurally different, deterministic
algorithm) and against the known secret on the same instances -- never against
the symmetric variant's own internal consistency.
"""

from __future__ import annotations

import random

import pytest

from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.research.ecdlp.bsgs import baby_step_giant_step
from keylab.research.ecdlp.negation_map import pollard_kangaroo_symmetric


def test_symmetric_matches_bsgs_and_secret() -> None:
    rng = random.Random(19)
    for _ in range(10):
        lo = rng.randrange(1, 10_000)
        hi = lo + rng.randrange(1, 4_096)
        k = rng.randrange(lo, hi + 1)
        q = scalar_mult(k, G)
        got = pollard_kangaroo_symmetric(q, lo, hi)
        assert got == k == baby_step_giant_step(q, lo, hi)


def test_symmetric_endpoints_and_width_zero() -> None:
    lo, hi = 1000, 1000 + 2048
    for k in (lo, hi, (lo + hi) // 2):
        assert pollard_kangaroo_symmetric(scalar_mult(k, G), lo, hi) == k
    assert pollard_kangaroo_symmetric(scalar_mult(55, G), 55, 55) == 55
    assert pollard_kangaroo_symmetric(scalar_mult(56, G), 55, 55) is None


def test_symmetric_forward_verified() -> None:
    k = 0xBEEF1
    got = pollard_kangaroo_symmetric(scalar_mult(k, G), k - 2500, k + 2500)
    assert got is not None and scalar_mult(got, G) == scalar_mult(k, G)


def test_symmetric_returns_none_out_of_interval() -> None:
    assert pollard_kangaroo_symmetric(scalar_mult(50_000, G), 1, 2048, max_steps=5000) is None


@pytest.mark.parametrize("lo,hi", [(-1, 10), (10, 5), (0, N)])
def test_symmetric_rejects_bad_intervals(lo, hi) -> None:
    with pytest.raises((ValueError, TypeError)):
        pollard_kangaroo_symmetric(scalar_mult(7, G), lo, hi)


def test_symmetric_rejects_bad_dp_bits() -> None:
    with pytest.raises(ValueError):
        pollard_kangaroo_symmetric(scalar_mult(7, G), 1, 10, dp_bits=0)
