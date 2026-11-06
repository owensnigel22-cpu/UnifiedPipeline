"""Pollard's rho DLP (educational).

Correctness is verified on a small toy curve against an INDEPENDENT brute-force
scan (rho's recovered k must equal the linear-scan k). The secp256k1 wrapper is
checked for the full-group wall (bounded budget -> None) and input validation.
A recovery test on secp256k1 itself is impossible -- every point has order N, so
rho needs ~2**128 steps; that is exactly the point, and it is asserted as the
wall, not worked around.
"""

from __future__ import annotations

import random

import pytest

from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.research.ecdlp.rho import RhoResult, pollard_rho, pollard_rho_dlog

# --- a tiny curve, purely for the test's independent reference -----------------------------------

class _ToyCurve:
    def __init__(self, p: int, a: int, b: int) -> None:
        self.p, self.a, self.b = p, a, b

    def add(self, P, Q):
        p, a = self.p, self.a
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P == Q:
            m = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
        else:
            m = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (m * m - x1 - x2) % p
        y3 = (m * (x1 - x3) - y1) % p
        return (x3, y3)

    def mul(self, k, P):
        R = None
        while k > 0:
            if k & 1:
                R = self.add(R, P)
            P = self.add(P, P)
            k >>= 1
        return R


def _legendre(a, p):
    return pow(a % p, (p - 1) // 2, p)


def _order(C):
    n = 1
    for x in range(C.p):
        rhs = (x * x * x + C.a * x + C.b) % C.p
        if rhs == 0:
            n += 1
        elif _legendre(rhs, C.p) == 1:
            n += 2
    return n


def _factor(n):
    f, d = {}, 2
    while d * d <= n:
        while n % d == 0:
            f[d] = f.get(d, 0) + 1
            n //= d
        d += 1
    if n > 1:
        f[n] = f.get(n, 0) + 1
    return f


def _toy_prime_subgroup():
    """A toy curve + a prime-order generator, built from scratch (no rho involved)."""
    C = _ToyCurve(10007, 1, 3)
    order = _order(C)
    q = max(_factor(order))  # largest prime factor
    # find a base point of order q
    for x in range(2, C.p):
        rhs = (x * x * x + C.a * x + C.b) % C.p
        if _legendre(rhs, C.p) == 1:
            y = pow(rhs, (C.p + 1) // 4, C.p)  # p % 4 == 3 for 10007
            P0 = (x, y)
            base = C.mul(order // q, P0)
            if base is not None and C.mul(q, base) is None:
                return C, base, q
    raise AssertionError("no prime-order generator found")


def _bruteforce_dlog(C, base, target, q):
    """Independent reference: linear scan for k with target == k*base."""
    cur = None
    for k in range(q):
        if cur == target:
            return k
        cur = C.add(cur, base)
    return None


def test_rho_recovers_dlog_on_toy_curve_vs_bruteforce() -> None:
    C, base, q = _toy_prime_subgroup()
    hasher = lambda pt: 0 if pt is None else pt[0]
    rng = random.Random(3)
    recovered = 0
    for _ in range(8):
        k = rng.randrange(1, q)
        target = C.mul(k, base)
        got = None
        for seed in range(1, 12):  # retry degenerate collisions
            got = pollard_rho_dlog(C.add, base, target, q, hasher=hasher, seed=seed)
            if got is not None and C.mul(got % q, base) == target:
                break
        assert got is not None
        assert got % q == _bruteforce_dlog(C, base, target, q) == k  # independent ref
        recovered += 1
    assert recovered == 8


def test_rho_dlog_rejects_bad_order() -> None:
    with pytest.raises(ValueError, match="order"):
        pollard_rho_dlog(lambda a, b: a, 0, 0, 1, hasher=lambda p: 0)


# --- secp256k1 wrapper: the full-group wall + validation -----------------------------------------

def test_rho_secp256k1_full_group_is_a_wall() -> None:
    # No budget recovers a full-group dlog; a bounded run returns None, not a wrong key.
    state = pollard_rho(scalar_mult(123456, G), 0, N - 1, max_steps=2000, return_state=True)
    assert isinstance(state, RhoResult)
    assert state.solution is None
    assert state.spent_steps > 0


def test_rho_secp256k1_bare_return() -> None:
    out = pollard_rho(scalar_mult(5, G), 0, N - 1, max_steps=500)
    assert out is None and not isinstance(out, RhoResult)


@pytest.mark.parametrize("lo,hi", [(-1, 10), (10, 5), (0, N)])
def test_rho_rejects_bad_intervals(lo, hi) -> None:
    with pytest.raises((ValueError, TypeError)):
        pollard_rho(scalar_mult(7, G), lo, hi)


def test_rho_rejects_non_integer_bounds() -> None:
    with pytest.raises(TypeError):
        pollard_rho(scalar_mult(7, G), 1.0, 10)  # type: ignore[arg-type]
