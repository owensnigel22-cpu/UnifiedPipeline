"""Deterministic tests for division polynomials, quartic inversion, and point halving."""

from __future__ import annotations

import random

import pytest

from keylab.ec.division_polynomials import (
    division_polynomials,
    multiplication_by_n_x,
    poly_degree,
    poly_divmod,
    poly_mul,
    poly_sub,
    poly_trim,
    x_of_multiple,
)
from keylab.ec.halving import (
    HALF_SCALAR,
    curve_double_affine,
    double_point,
    doubling_preimages,
    halve_point,
    halve_point_via_quartic,
    halving_chain,
)
from keylab.ec.quartic import doubling_quartic, invert_doubling_x, roots_mod_p
from keylab.ec.secp256k1 import G, N, P, scalar_mult

RNG = random.Random(0x4A1F)
SECP_POINTS = [scalar_mult(RNG.randrange(1, N), G, backend="python") for _ in range(4)]
# Toy curves y^2 = x^3 + ax + b found by exhaustive search; see docs/point_halving.md.
TOY_FULL_TWO_TORSION_P3 = (102, 0, 103)   # y^2 = x^3 - x, #E = 104, p = 3 (mod 4)
TOY_FULL_TWO_TORSION_P1 = (112, 0, 113)   # y^2 = x^3 - x, #E = 128, p = 1 (mod 4)
TOY_ODD_ORDER = (0, 7, 1009)              # secp256k1's equation over a small prime, #E = 1029


def _toy_points(a: int, b: int, p: int) -> list[tuple[int, int]]:
    return [(x, y) for x in range(p) for y in range(p) if (y * y - (x ** 3 + a * x + b)) % p == 0]


def _toy_add(left, right, a: int, p: int):
    if left is None:
        return right
    if right is None:
        return left
    if left[0] == right[0] and (left[1] + right[1]) % p == 0:
        return None
    if left == right:
        return curve_double_affine(left, a, p)
    slope = (right[1] - left[1]) * pow(right[0] - left[0], -1, p) % p
    x3 = (slope * slope - left[0] - right[0]) % p
    return x3, (slope * (left[0] - x3) - left[1]) % p


# --- division polynomials -------------------------------------------------

def test_division_polynomial_degrees_on_secp256k1() -> None:
    f = division_polynomials(9)
    assert f[0] == [] and f[1] == [1] and f[2] == [1]
    for n in range(3, 10):
        expected = (n * n - 1) // 2 if n % 2 else (n * n - 4) // 2
        assert poly_degree(f[n]) == expected


def test_psi3_matches_closed_form_for_secp256k1() -> None:
    # psi_3 = 3x^4 + 6ax^2 + 12bx - a^2 with a = 0, b = 7.
    assert division_polynomials(3)[3] == poly_trim([0, 84, 0, 0, 3], P)


@pytest.mark.parametrize("n", range(1, 9))
def test_multiplication_formula_matches_scalar_multiplication_on_secp256k1(n: int) -> None:
    for point in SECP_POINTS:
        assert x_of_multiple(n, point[0]) == scalar_mult(n, point, backend="python")[0]


@pytest.mark.parametrize("curve", [TOY_FULL_TWO_TORSION_P3, TOY_ODD_ORDER])
def test_multiplication_formula_and_torsion_on_toy_curves(curve: tuple[int, int, int]) -> None:
    a, b, p = curve
    points = _toy_points(a, b, p)
    for n in range(2, 7):
        for point in points[::7]:
            multiple = None
            for _ in range(n):
                multiple = _toy_add(multiple, point, a, p)
            predicted = x_of_multiple(n, point[0], a, b, p)
            assert predicted == (None if multiple is None else multiple[0])


def test_doubling_numerator_minus_target_equals_the_quartic() -> None:
    numerator, denominator = multiplication_by_n_x(2)
    x_q = SECP_POINTS[0][0]
    assert poly_sub(numerator, poly_mul([x_q], denominator, P), P) == doubling_quartic(x_q)


# --- quartic root finding --------------------------------------------------

def test_roots_mod_p_recovers_planted_roots_in_the_secp256k1_field() -> None:
    planted = sorted({RNG.randrange(P) for _ in range(5)})
    poly = [1]
    for root in planted:
        poly = poly_mul(poly, [-root, 1], P)
    poly = poly_mul(poly, [3, 0, 1], P)  # x^2 + 3 contributes roots only if -3 is a square
    roots = roots_mod_p(poly)
    assert set(planted) <= set(roots)
    for root in roots:
        _, remainder = poly_divmod(poly, [-root, 1], P)
        assert remainder == []


def test_roots_mod_p_returns_nothing_for_an_irreducible_quadratic() -> None:
    non_residue = next(c for c in range(2, 100) if pow(c, (P - 1) // 2, P) == P - 1)
    assert roots_mod_p([-non_residue, 0, 1]) == []


def test_quartic_has_exactly_one_curve_root_on_secp256k1() -> None:
    for point in SECP_POINTS:
        roots = invert_doubling_x(point[0])
        curve_roots = [root for root in roots if root.on_curve]
        assert len(curve_roots) == 1
        assert all(not root.on_curve and not root.y_values for root in roots if root not in curve_roots)


# --- halving -----------------------------------------------------------------

def test_half_scalar_is_the_inverse_of_two() -> None:
    assert 2 * HALF_SCALAR % N == 1


@pytest.mark.parametrize("index", range(len(SECP_POINTS)))
def test_halving_inverts_doubling_and_both_routes_agree(index: int) -> None:
    point = SECP_POINTS[index]
    half = halve_point(point)
    assert double_point(half) == point
    assert halve_point_via_quartic(point) == half
    assert halve_point(double_point(point)) == point


def test_halving_a_known_multiple_halves_its_scalar_mod_n() -> None:
    # Halving dG gives (d/2 mod N)G: the discrete log is transformed, never revealed.
    d = 0x1234567
    assert halve_point(scalar_mult(d, G)) == scalar_mult(d * HALF_SCALAR % N, G)
    assert halve_point(scalar_mult(2 * d, G)) == scalar_mult(d, G)


def test_halving_chain_matches_inverse_powers_of_two() -> None:
    chain = halving_chain(SECP_POINTS[1], 6)
    for k, half in enumerate(chain, start=1):
        assert half == scalar_mult(pow(2, -k, N), SECP_POINTS[1], backend="python")
        assert scalar_mult(2 ** k, half, backend="python") == SECP_POINTS[1]
    assert halving_chain(SECP_POINTS[1], 0) == []
    with pytest.raises(ValueError):
        halving_chain(SECP_POINTS[1], -1)


@pytest.mark.parametrize("curve,group_order", [(TOY_FULL_TWO_TORSION_P3, 104),
                                               (TOY_FULL_TWO_TORSION_P1, 128)])
def test_full_two_torsion_curves_have_four_or_zero_halves(curve: tuple[int, int, int],
                                                         group_order: int) -> None:
    a, b, p = curve
    points = _toy_points(a, b, p)
    assert len(points) + 1 == group_order
    counts = [len(doubling_preimages(point, a, b, p)) for point in points]
    assert set(counts) == {0, 4}
    # Doubling is 4-to-1 onto 2E, so |2E| = |E| / 4 (one of which is infinity).
    assert counts.count(4) == group_order // 4 - 1
    for point in points[::5]:
        for preimage in doubling_preimages(point, a, b, p):
            assert curve_double_affine(preimage, a, p) == point


def test_odd_order_toy_curve_has_unique_halves() -> None:
    a, b, p = TOY_ODD_ORDER
    points = _toy_points(a, b, p)
    assert len(points) + 1 == 1029
    assert all(len(doubling_preimages(point, a, b, p)) == 1 for point in points[::11])


def test_doubling_preimages_rejects_off_curve_targets() -> None:
    with pytest.raises(ValueError):
        doubling_preimages((1, 1))
    assert halve_point(None) is None
    assert curve_double_affine(None) is None
