"""Point halving and doubling-inversion helpers.

Research/teaching module.

*Halving* finds H with 2H = Q. In a group of odd order N (secp256k1's order is
prime) doubling is a bijection, so the half is unique and equals
``((N + 1) / 2) · Q``, since (N + 1)/2 is the inverse of 2 modulo N.
:func:`halve_point` uses that one-line identity; :func:`halve_point_via_quartic`
reaches the same point from first principles by solving the doubling quartic
in :mod:`keylab.ec.quartic`, which is the useful part for study.

What halving does *not* do: if Q = dG then the half is (d/2 mod N)·G, a
point whose discrete logarithm is just as unknown as d. Repeated halving,
"walking back" from a public key, or comparing halves gives no information
about d. Point halving is known in the literature as a *speed* technique for
binary-field curves (Knudsen; Schroeppel), where it can be cheaper than
doubling; over prime fields such as secp256k1 it is slower than doubling.

The generic helpers accept any short-Weierstrass curve ``y^2 = x^3 + ax + b``
over F_p so that tests can show multiple preimages on small even-order curves.
"""

from __future__ import annotations

from keylab.ec.quartic import invert_doubling_x
from keylab.ec.secp256k1 import N, P, Point, point_add_affine, require_point, scalar_mult

HALF_SCALAR = (N + 1) // 2  # 2 * HALF_SCALAR == 1 (mod N)


def curve_double_affine(point: tuple[int, int] | None, a: int = 0,
                        p: int = P) -> tuple[int, int] | None:
    """Tangent-line doubling on ``y^2 = x^3 + ax + b`` (b does not appear in the formula)."""
    if point is None:
        return None
    x, y = point
    if y % p == 0:
        return None  # 2-torsion point: the tangent is vertical
    slope = (3 * x * x + a) * pow(2 * y, -1, p) % p
    x3 = (slope * slope - 2 * x) % p
    return x3, (slope * (x - x3) - y) % p


def double_point(point: Point) -> Point:
    """Double a secp256k1 point."""
    return point_add_affine(point, point)


def halve_point(point: Point) -> Point:
    """Return the unique secp256k1 point H with 2H == point (scalar shortcut)."""
    if point is None:
        return None
    return scalar_mult(HALF_SCALAR, require_point(point), backend="python")


def doubling_preimages(target: tuple[int, int], a: int = 0, b: int = 7,
                       p: int = P) -> tuple[tuple[int, int], ...]:
    """Return every rational point R with 2R == target on ``y^2 = x^3 + ax + b`` over F_p.

    Works by solving the doubling quartic for x(R), lifting curve roots to
    both y values, and keeping those that double to ``target`` (the other sign
    doubles to ``-target``). On secp256k1 the result has exactly one point;
    on a curve whose group has rational 2-torsion it can have 2 or 4.
    """
    x_q, y_q = target
    if (y_q * y_q - (x_q ** 3 + a * x_q + b)) % p:
        raise ValueError("target is not on the curve")
    preimages = []
    for root in invert_doubling_x(x_q, a, b, p):
        for y in root.y_values:
            if curve_double_affine((root.x, y), a, p) == (x_q % p, y_q % p):
                preimages.append((root.x, y))
    return tuple(sorted(preimages))


def halve_point_via_quartic(point: tuple[int, int]) -> tuple[int, int]:
    """Halve a secp256k1 point by solving the doubling quartic (research path)."""
    preimages = doubling_preimages(require_point(point))
    if len(preimages) != 1:
        raise ArithmeticError("secp256k1 has odd order, so exactly one half must exist")
    return preimages[0]


def halving_chain(point: tuple[int, int], steps: int) -> list[tuple[int, int]]:
    """Return successive halves ``Q/2, Q/4, ...`` (``steps`` entries).

    Each entry k equals ``(2^-k mod N) · Q``; see the module docstring for why
    this reveals nothing about Q's discrete logarithm.
    """
    if type(steps) is not int or not 0 <= steps <= 4096:
        raise ValueError("steps must be an integer in [0, 4096]")
    chain = []
    current = require_point(point)
    for _ in range(steps):
        half = halve_point(current)
        assert half is not None
        chain.append(half)
        current = half
    return chain


__all__ = [
    "HALF_SCALAR",
    "curve_double_affine",
    "double_point",
    "doubling_preimages",
    "halve_point",
    "halve_point_via_quartic",
    "halving_chain",
]
