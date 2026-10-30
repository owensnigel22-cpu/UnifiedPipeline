"""Division polynomials for short-Weierstrass curves ``y^2 = x^3 + ax + b`` over F_p.

Research/teaching module. Division polynomials ψ_n describe multiplication by
``n`` purely in terms of the x coordinate::

    x(nP) = x - ψ_{n-1} ψ_{n+1} / ψ_n^2

and the roots of ψ_n are the x coordinates of the n-torsion points. For
secp256k1 the group order N is prime, so no rational point other than infinity
has small order; roots of ψ_n that exist in F_p belong to the quadratic twist
or to extension-field points. Nothing here helps solve the discrete logarithm.

Representation. ψ_n contains a factor ``y`` exactly when n is even, so we store
the x-only polynomial ``f_n`` with::

    ψ_n = f_n            (n odd)
    ψ_n = 2y · f_n       (n even)

and substitute ``(2y)^2 = F(x) = 4(x^3 + ax + b)`` wherever y^2 appears.
Polynomials are coefficient lists, lowest degree first, reduced modulo p.
"""

from __future__ import annotations

from collections.abc import Sequence

from keylab.ec.secp256k1 import P as SECP256K1_P

Poly = list[int]


# ---------------------------------------------------------------------------
# Polynomial arithmetic over F_p
# ---------------------------------------------------------------------------

def poly_trim(poly: Sequence[int], p: int) -> Poly:
    """Reduce coefficients mod p and drop leading zeros (``[]`` is the zero polynomial)."""
    out = [c % p for c in poly]
    while out and out[-1] == 0:
        out.pop()
    return out


def poly_degree(poly: Sequence[int]) -> int:
    """Degree of a trimmed polynomial; the zero polynomial has degree -1."""
    return len(poly) - 1


def poly_add(left: Sequence[int], right: Sequence[int], p: int) -> Poly:
    size = max(len(left), len(right))
    return poly_trim([(left[i] if i < len(left) else 0) + (right[i] if i < len(right) else 0)
                      for i in range(size)], p)


def poly_sub(left: Sequence[int], right: Sequence[int], p: int) -> Poly:
    return poly_add(left, [-c for c in right], p)


def poly_scale(poly: Sequence[int], scalar: int, p: int) -> Poly:
    return poly_trim([c * scalar for c in poly], p)


def poly_mul(left: Sequence[int], right: Sequence[int], p: int) -> Poly:
    if not left or not right:
        return []
    out = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        if a:
            for j, b in enumerate(right):
                out[i + j] += a * b
    return poly_trim(out, p)


def poly_divmod(numerator: Sequence[int], divisor: Sequence[int], p: int) -> tuple[Poly, Poly]:
    """Polynomial long division over the prime field F_p."""
    divisor = poly_trim(divisor, p)
    if not divisor:
        raise ZeroDivisionError("polynomial division by zero")
    remainder = poly_trim(numerator, p)
    inverse_lead = pow(divisor[-1], -1, p)
    quotient = [0] * max(len(remainder) - len(divisor) + 1, 0)
    while len(remainder) >= len(divisor):
        shift = len(remainder) - len(divisor)
        factor = remainder[-1] * inverse_lead % p
        quotient[shift] = factor
        for i, c in enumerate(divisor):
            remainder[shift + i] = (remainder[shift + i] - factor * c) % p
        remainder = poly_trim(remainder, p)
    return poly_trim(quotient, p), remainder


def poly_mod(poly: Sequence[int], modulus: Sequence[int], p: int) -> Poly:
    return poly_divmod(poly, modulus, p)[1]


def poly_monic(poly: Sequence[int], p: int) -> Poly:
    poly = poly_trim(poly, p)
    return poly_scale(poly, pow(poly[-1], -1, p), p) if poly else []


def poly_gcd(left: Sequence[int], right: Sequence[int], p: int) -> Poly:
    """Monic greatest common divisor."""
    a, b = poly_trim(left, p), poly_trim(right, p)
    while b:
        a, b = b, poly_mod(a, b, p)
    return poly_monic(a, p)


def poly_pow_mod(base: Sequence[int], exponent: int, modulus: Sequence[int], p: int) -> Poly:
    """Compute ``base^exponent mod modulus`` by square-and-multiply."""
    if exponent < 0:
        raise ValueError("exponent must be non-negative")
    result: Poly = poly_mod([1], modulus, p)
    square = poly_mod(base, modulus, p)
    while exponent:
        if exponent & 1:
            result = poly_mod(poly_mul(result, square, p), modulus, p)
        square = poly_mod(poly_mul(square, square, p), modulus, p)
        exponent >>= 1
    return result


def poly_eval(poly: Sequence[int], x: int, p: int) -> int:
    """Horner evaluation at ``x`` modulo p."""
    value = 0
    for c in reversed(poly):
        value = (value * x + c) % p
    return value


# ---------------------------------------------------------------------------
# Division polynomials
# ---------------------------------------------------------------------------

def curve_rhs(a: int = 0, b: int = 7, p: int = SECP256K1_P) -> Poly:
    """The cubic ``x^3 + ax + b``."""
    return poly_trim([b, a, 0, 1], p)


def _two_y_squared(a: int, b: int, p: int) -> Poly:
    """``F(x) = (2y)^2 = 4(x^3 + ax + b)``."""
    return poly_scale(curve_rhs(a, b, p), 4, p)


def division_polynomials(n_max: int, a: int = 0, b: int = 7, p: int = SECP256K1_P) -> list[Poly]:
    """Return the reduced division polynomials ``[f_0, f_1, ..., f_{n_max}]``.

    See the module docstring for the relationship between ``f_n`` and ψ_n.
    Degrees are ``(n^2 - 1)/2`` for odd n and ``(n^2 - 4)/2`` for even n
    (when ``n`` is not divisible by p).
    """
    if type(n_max) is not int or n_max < 0:
        raise ValueError("n_max must be a non-negative integer")
    two_y_sq = _two_y_squared(a, b, p)
    f_sq = poly_mul(two_y_sq, two_y_sq, p)  # F^2
    f: list[Poly] = [
        [],
        [1],
        [1],
        poly_trim([-a * a, 12 * b, 6 * a, 0, 3], p),
        poly_scale(poly_trim([-8 * b * b - a ** 3, -4 * a * b, -5 * a * a, 20 * b, 5 * a, 0, 1], p), 2, p),
    ]
    for n in range(5, n_max + 1):
        m = n // 2
        if n % 2:  # n = 2m + 1
            first = poly_mul(f[m + 2], poly_mul(f[m], poly_mul(f[m], f[m], p), p), p)
            second = poly_mul(f[m - 1], poly_mul(f[m + 1], poly_mul(f[m + 1], f[m + 1], p), p), p)
            if m % 2 == 0:
                first = poly_mul(f_sq, first, p)
            else:
                second = poly_mul(f_sq, second, p)
            f.append(poly_sub(first, second, p))
        else:  # n = 2m
            inner = poly_sub(
                poly_mul(f[m + 2], poly_mul(f[m - 1], f[m - 1], p), p),
                poly_mul(f[m - 2], poly_mul(f[m + 1], f[m + 1], p), p),
                p,
            )
            f.append(poly_mul(f[m], inner, p))
    return f[: n_max + 1]


def psi_squared(n: int, a: int = 0, b: int = 7, p: int = SECP256K1_P,
                table: Sequence[Poly] | None = None) -> Poly:
    """Return ψ_n^2 as a polynomial in x."""
    f = table if table is not None else division_polynomials(n, a, b, p)
    square = poly_mul(f[n], f[n], p)
    return square if n % 2 else poly_mul(_two_y_squared(a, b, p), square, p)


def multiplication_by_n_x(n: int, a: int = 0, b: int = 7,
                          p: int = SECP256K1_P) -> tuple[Poly, Poly]:
    """Return ``(φ_n, ψ_n^2)`` with ``x(nP) = φ_n(x) / ψ_n(x)^2``.

    ``φ_n = x ψ_n^2 - ψ_{n+1} ψ_{n-1}``; for n = 2 this is the doubling formula.
    """
    if type(n) is not int or n < 1:
        raise ValueError("n must be a positive integer")
    f = division_polynomials(n + 1, a, b, p)
    denominator = psi_squared(n, a, b, p, f)
    neighbours = poly_mul(f[n + 1], f[n - 1], p)
    if n % 2:  # n±1 even: ψ_{n+1}ψ_{n-1} = F f_{n+1} f_{n-1}
        neighbours = poly_mul(_two_y_squared(a, b, p), neighbours, p)
    numerator = poly_sub(poly_mul([0, 1], denominator, p), neighbours, p)
    return numerator, denominator


def x_of_multiple(n: int, x: int, a: int = 0, b: int = 7, p: int = SECP256K1_P) -> int | None:
    """Evaluate ``x(nP)`` from ``x(P)`` alone; ``None`` means nP is the point at infinity."""
    numerator, denominator = multiplication_by_n_x(n, a, b, p)
    den = poly_eval(denominator, x, p)
    if den == 0:
        return None
    return poly_eval(numerator, x, p) * pow(den, -1, p) % p


__all__ = [
    "Poly",
    "curve_rhs",
    "division_polynomials",
    "multiplication_by_n_x",
    "poly_add",
    "poly_degree",
    "poly_divmod",
    "poly_eval",
    "poly_gcd",
    "poly_mod",
    "poly_monic",
    "poly_mul",
    "poly_pow_mod",
    "poly_scale",
    "poly_sub",
    "poly_trim",
    "psi_squared",
    "x_of_multiple",
]
