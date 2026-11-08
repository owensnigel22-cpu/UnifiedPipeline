"""Bounded nonce pre-image recovery (educational).

Verified against the KNOWN nonce: build R = k*G for a chosen k in range, take
r = R.x mod N, and require recovery to return exactly k (forward-verified via an
independent scalar multiplication). Both solver methods must agree.
"""

from __future__ import annotations

import random

import pytest

from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.research.ecdsa import recover_nonce_in_range


def test_recovers_bounded_nonce_both_methods() -> None:
    rng = random.Random(2024)
    for _ in range(5):
        lo = rng.randrange(1, 100_000)
        hi = lo + rng.randrange(1, 4_000)
        k = rng.randrange(lo, hi + 1)
        r = scalar_mult(k, G)[0] % N
        for method in ("bsgs", "kangaroo"):
            got = recover_nonce_in_range(r, lo, hi, method=method)
            assert got == k, f"{method}: k={k} got={got}"
            assert scalar_mult(got, G)[0] % N == r  # independent check


def test_returns_none_when_nonce_outside_range() -> None:
    k = 500_000
    r = scalar_mult(k, G)[0] % N
    assert recover_nonce_in_range(r, 1, 2048, method="bsgs") is None


def test_rejects_bad_inputs() -> None:
    k = 1234
    r = scalar_mult(k, G)[0] % N
    with pytest.raises(ValueError, match="r must be"):
        recover_nonce_in_range(0, 1, 10)
    with pytest.raises(ValueError, match="bounded range"):
        recover_nonce_in_range(r, 10, 5)
    with pytest.raises(ValueError, match="method"):
        recover_nonce_in_range(r, 1, 10, method="magic")
    with pytest.raises(TypeError):
        recover_nonce_in_range(r, 1.0, 10)  # type: ignore[arg-type]
