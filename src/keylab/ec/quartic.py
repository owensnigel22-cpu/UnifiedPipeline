"""Quartic inversion of the doubling map on ``y^2 = x^3 + ax + b`` (secp256k1 by default).

Research/teaching module. Doubling a point P = (x, y) gives::

    x(2P) = (x^4 - 2a x^2 - 8b x + a^2) / (4(x^3 + ax + b))

so the x coordinates of every "half" of a target Q are the roots of the quartic::

    x^4 - 4 x_Q x^3 - 2a x^2 - (8b + 4a x_Q) x + (a^2 - 4b x_Q) = 0

(for secp256k1, a = 0 and b = 7: ``x^4 - 4 x_Q x^3 - 56 x - 28 x_Q``).

Over the algebraic closure the four roots are x(H + T) for the four 2-torsion
points T. For secp256k1 the group order N is odd, so exactly one root lifts to
a point of E(F_p) whose double is ±Q; any other root in F_p has a non-square
``x^3 + 7`` and belongs to the quadratic twist. Recovering a half this way is
equivalent to multiplying by ``(N + 1) / 2`` and reveals nothing about the
discrete logarithm of Q.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from keylab.ec.division_polynomials import (
    Poly,
    poly_degree,
    poly_divmod,
    poly_eval,
    poly_gcd,
    poly_monic,
    poly_pow_mod,
    poly_sub,
    poly_trim,
)
from keylab.ec.secp256k1 import P as SECP256K1_P

_MAX_SPLIT_ATTEMPTS = 512
_BRUTE_FORCE_FIELD_LIMIT = 4096


def _equal_degree_split(poly: Poly, p: int) -> list[int]:
    """Return the roots of a squarefree, fully split monic polynomial.

    Deterministic Cantor-Zassenhaus variant: try shifts a = 0, 1, 2, ... and
    split with gcd(poly, (x + a)^((p-1)/2) - 1), which separates roots r by the
    quadratic character of r + a.
    """
    degree = poly_degree(poly)
    if degree == 0:
        return []
    if degree == 1:
        return [(-poly[0]) * pow(poly[1], -1, p) % p]
    for shift in range(_MAX_SPLIT_ATTEMPTS):
        candidate = poly_sub(poly_pow_mod([shift, 1], (p - 1) // 2, poly, p), [1], p)
        factor = poly_gcd(poly, candidate, p)
        if 0 < poly_degree(factor) < degree:
            cofactor, remainder = poly_divmod(poly, factor, p)
            assert not remainder
            return _equal_degree_split(factor, p) + _equal_degree_split(poly_monic(cofactor, p), p)
    raise ArithmeticError("root splitting did not converge; increase the attempt bound")


def roots_mod_p(poly: Sequence[int], p: int = SECP256K1_P) -> list[int]:
    """Return the distinct roots in F_p of a polynomial over F_p, sorted ascending.

    Computes ``gcd(f, x^p - x)`` (the product of linear factors) and then splits it.
    """
    f = poly_monic(poly_trim(poly, p), p)
    if not f:
        raise ValueError("the zero polynomial has every element as a root")
    if poly_degree(f) == 0:
        return []
    if p < _BRUTE_FORCE_FIELD_LIMIT:
        # Tiny research fields: exhaustive evaluation is exact and simplest.
        return [r for r in range(p) if poly_eval(f, r, p) == 0]
    x_to_p = poly_pow_mod([0, 1], p, f, p)
    linear_part = poly_gcd(f, poly_sub(x_to_p, [0, 1], p), p)
    return sorted(set(_equal_degree_split(linear_part, p)))


def doubling_quartic(x_q: int, a: int = 0, b: int = 7, p: int = SECP256K1_P) -> Poly:
    """Coefficients (lowest degree first) of the quartic whose roots satisfy x(2H) = x_q."""
    if not 0 <= x_q < p:
        raise ValueError("x_q must be a field element")
    return poly_trim([a * a - 4 * b * x_q, -(8 * b + 4 * a * x_q), -2 * a, -4 * x_q, 1], p)


@dataclass(frozen=True)
class QuarticRoot:
    """One F_p root of the doubling quartic and where it lives."""

    x: int
    rhs: int            # x^3 + ax + b
    on_curve: bool      # True when rhs is a square, so (x, ±y) is in E(F_p)
    y_values: tuple[int, ...]


def _sqrt_mod(value: int, p: int) -> int | None:
    value %= p
    if value == 0:
        return 0
    if pow(value, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(value, (p + 1) // 4, p)
    # Tonelli-Shanks for p = 1 (mod 4), needed only for toy research curves.
    q, s = p - 1, 0
    while q % 2 == 0:
        q, s = q // 2, s + 1
    z = next(c for c in range(2, p) if pow(c, (p - 1) // 2, p) == p - 1)
    m, c, t, r = s, pow(z, q, p), pow(value, q, p), pow(value, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2, i = t2 * t2 % p, i + 1
        bb = pow(c, 1 << (m - i - 1), p)
        m, c, t, r = i, bb * bb % p, t * bb * bb % p, r * bb % p
    return r


def invert_doubling_x(x_q: int, a: int = 0, b: int = 7, p: int = SECP256K1_P) -> list[QuarticRoot]:
    """Solve the doubling quartic and classify each F_p root as curve or twist."""
    roots = []
    for x in roots_mod_p(doubling_quartic(x_q, a, b, p), p):
        rhs = (x * x * x + a * x + b) % p
        y = _sqrt_mod(rhs, p)
        ys = () if y is None else tuple(sorted({y, (-y) % p}))
        roots.append(QuarticRoot(x, rhs, y is not None, ys))
    return roots


__all__ = ["QuarticRoot", "doubling_quartic", "invert_doubling_x", "roots_mod_p"]
