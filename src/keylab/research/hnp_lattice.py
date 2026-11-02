"""Synthetic, tiny-parameter Hidden Number Problem (HNP) lattice demonstration.

The HNP asks: recover a secret ``x`` given samples ``t_i = a_i*x + e_i (mod q)``
with public ``a_i`` and small, bounded errors ``e_i``. Embedding the samples in a
lattice and reducing it (LLL) then finding the closest vector (Babai) recovers
``x`` when the errors are small enough. This module shows that *mechanism* on a toy
modulus; it is not an ECDSA, signature, wallet, or private-key recovery tool, and
it has no secp256k1, WIF, HD-wallet, file-input, or network interface.

Limitations:

* Recovery is not guaranteed to be fast; the included LLL is a tiny pedagogical
  implementation with an iteration cap, not an optimized reducer.
* A successful reduction does **not** guarantee the correct ``x`` on adversarial
  inputs: the shortest/closest vector found can be a wrong short vector that does
  not encode the secret.
* Error-bound verification (``|e_i| <= ERROR_BOUND``) is necessary but **not
  sufficient** for correctness on untrusted samples -- it confirms the returned
  vector fits the stated leakage model, not that the model matched reality.

The modulus is capped at 100,000: production-sized moduli (e.g. a 256-bit group
order) are rejected, because this demo neither scales to nor is meaningful for
them.
"""

from __future__ import annotations

from collections.abc import Sequence
from fractions import Fraction
from random import Random

TOY_Q = 1009
TOY_X = 37
SAMPLE_COUNT = 8
ERROR_BOUND = 2
SEED = 20261021
MAX_MODULUS = 100_000


# --- input validation ---------------------------------------------------------------------------

def _validate_modulus(q: int) -> None:
    """Reject non-integer, degenerate, or production-sized moduli."""
    if type(q) is not int:
        raise TypeError("modulus q must be an integer")
    if q <= 1:
        raise ValueError("modulus q must be greater than 1")
    if q > MAX_MODULUS:
        raise ValueError(f"modulus q must be <= {MAX_MODULUS}; this is a toy demonstration only")


def _validate_basis(basis: Sequence[Sequence[int]]) -> tuple[int, int]:
    """Return (rows, width) after rejecting ragged, empty, or non-integer matrices."""
    if not isinstance(basis, (list, tuple)) or len(basis) == 0:
        raise ValueError("basis must be a non-empty list of rows")
    width = None
    for row in basis:
        if not isinstance(row, (list, tuple)) or len(row) == 0:
            raise ValueError("each basis row must be a non-empty list")
        if width is None:
            width = len(row)
        elif len(row) != width:
            raise ValueError("basis rows must all have the same width (ragged matrix rejected)")
        for value in row:
            if type(value) is not int:
                raise TypeError("basis entries must be integers")
    assert width is not None
    return len(basis), width


def _validate_vector(vector: Sequence[int], width: int) -> None:
    if not isinstance(vector, (list, tuple)) or len(vector) != width:
        raise ValueError(f"vector must be a list of length {width}")
    for value in vector:
        if type(value) is not int:
            raise TypeError("vector entries must be integers")


# --- lattice primitives (math unchanged from the reference toy) ---------------------------------

def _nearest_integer(value: Fraction) -> int:
    """Round a rational to nearest integer, ties away from zero."""
    if value < 0:
        return -_nearest_integer(-value)
    return (2 * value.numerator + value.denominator) // (2 * value.denominator)


def _gram_schmidt(
    basis: list[list[int]],
) -> tuple[list[list[Fraction]], list[list[Fraction]], list[Fraction]]:
    count, width = _validate_basis(basis)
    orthogonal: list[list[Fraction]] = []
    coefficients = [[Fraction(0) for _ in range(count)] for _ in range(count)]
    norms: list[Fraction] = []
    for i, vector in enumerate(basis):
        residual = [Fraction(value) for value in vector]
        for j in range(i):
            coefficients[i][j] = sum(Fraction(vector[k]) * orthogonal[j][k] for k in range(width)) / norms[j]
            residual = [residual[k] - coefficients[i][j] * orthogonal[j][k] for k in range(width)]
        orthogonal.append(residual)
        norms.append(sum((value * value for value in residual), Fraction(0)))
    return orthogonal, coefficients, norms


def _lll_reduce(basis: list[list[int]]) -> list[list[int]]:
    """Small pedagogical LLL implementation; intended only for this tiny demo."""
    _validate_basis(basis)
    reduced = [list(row) for row in basis]
    k = 1
    iterations = 0
    while k < len(reduced):
        iterations += 1
        if iterations > 20_000:
            raise RuntimeError("toy LLL iteration cap reached")
        _, mu, norms = _gram_schmidt(reduced)
        for j in range(k - 1, -1, -1):
            quotient = _nearest_integer(mu[k][j])
            if quotient:
                reduced[k] = [a - quotient * b for a, b in zip(reduced[k], reduced[j])]
                _, mu, norms = _gram_schmidt(reduced)
        if norms[k] >= (Fraction(3, 4) - mu[k][k - 1] ** 2) * norms[k - 1]:
            k += 1
        else:
            reduced[k], reduced[k - 1] = reduced[k - 1], reduced[k]
            k = max(1, k - 1)
    return reduced


def _babai_nearest_plane(basis: list[list[int]], target: list[int]) -> list[int]:
    """Return a nearby lattice vector using Babai's nearest-plane method."""
    _, width = _validate_basis(basis)
    _validate_vector(target, width)
    orthogonal, _, norms = _gram_schmidt(basis)
    residual = [Fraction(value) for value in target]
    for i in range(len(basis) - 1, -1, -1):
        coefficient = _nearest_integer(
            sum(residual[k] * orthogonal[i][k] for k in range(len(target))) / norms[i]
        )
        residual = [residual[k] - coefficient * basis[i][k] for k in range(len(target))]
    return [target[k] - int(residual[k]) for k in range(len(target))]


# --- synthetic instance + demo ------------------------------------------------------------------

def make_instance(q: int = TOY_Q) -> tuple[int, list[int], list[int], list[int]]:
    """Create a deterministic HNP instance ``t_i = a_i*x + e_i (mod q)`` with bounded ``e_i``.

    Returns ``(q, multipliers, observations, errors)``. ``q`` is validated and must
    be a toy modulus (``1 < q <= 100_000``).
    """
    _validate_modulus(q)
    rng = Random(SEED)
    multipliers = [rng.randrange(1, q) for _ in range(SAMPLE_COUNT)]
    errors = [rng.randrange(-ERROR_BOUND, ERROR_BOUND + 1) for _ in range(SAMPLE_COUNT)]
    observations = [(a * TOY_X + e) % q for a, e in zip(multipliers, errors)]
    return q, multipliers, observations, errors


def run_demo(q: int = TOY_Q) -> dict[str, object]:
    """Recover the synthetic toy ``x`` over modulus ``q`` and verify every equation.

    Returns a result dict. ``q`` is validated (``1 < q <= 100_000``); a
    production-sized modulus raises ``ValueError``.
    """
    q, multipliers, observations, _ = make_instance(q)
    dimension = len(multipliers)
    basis = [[q * int(i == j) for j in range(dimension)] + [0] for i in range(dimension)]
    basis.append(list(multipliers) + [1])

    reduced = _lll_reduce(basis)
    nearby = _babai_nearest_plane(reduced, list(observations) + [0])
    recovered = nearby[-1]
    residuals = [nearby[i] - observations[i] for i in range(dimension)]

    if recovered != TOY_X:
        raise AssertionError(f"toy recovery mismatch: expected {TOY_X}, got {recovered}")
    if any(abs(error) > ERROR_BOUND for error in residuals):
        raise AssertionError("recovered lattice vector does not satisfy the toy leakage bounds")
    if any((a * recovered - t - e) % q for a, t, e in zip(multipliers, observations, residuals)):
        raise AssertionError("toy modular equations did not verify")

    return {
        "modulus": q,
        "observations": dimension,
        "error_bound": ERROR_BOUND,
        "recovered_x": recovered,
        "residuals": residuals,
    }


def demo() -> int:
    """Print the toy HNP recovery and return the recovered ``x`` (for ``python -m``)."""
    result = run_demo(TOY_Q)
    recovered = result["recovered_x"]
    assert isinstance(recovered, int)
    print("Synthetic HNP lattice demo (toy modulus only)")
    print(f"modulus q: {result['modulus']}; observations: {result['observations']}; "
          f"error bound: +/-{result['error_bound']}")
    print(f"recovered toy x: {recovered}")
    print(f"verified residuals: {result['residuals']}")
    print("This demonstrates lattice mechanics; it is not an ECDSA or wallet-key recovery tool.")
    return recovered


__all__ = [
    "ERROR_BOUND",
    "MAX_MODULUS",
    "SAMPLE_COUNT",
    "SEED",
    "TOY_Q",
    "TOY_X",
    "demo",
    "make_instance",
    "run_demo",
]


if __name__ == "__main__":
    demo()
