"""GLV decomposition + interleaved wNAF for arbitrary-point k*P (M2.5).

The GLV+wNAF path is what ``scalar_mult(backend="auto")`` runs for an arbitrary
point with no native backend, also selectable as ``python-optimized``. Every
result is checked against the frozen reference (keylab.ec.reference) and, where
installed, coincurve and fastecdsa -- the four oracles required by
docs/PERFORMANCE_VALIDATION.md.
"""

from __future__ import annotations

import random

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from keylab.ec import reference as ref
from keylab.ec import secp256k1 as curve
from keylab.ec.secp256k1 import (
    _GLV_WNAF_WINDOW,
    BETA,
    LAMBDA,
    N,
    P,
    _scalar_mult_glv_wnaf,
    glv_decompose,
    point_add_affine,
    scalar_mult,
    wnaf_digits,
)

FAST = settings(max_examples=40, deadline=None)
OPT = "python-optimized"
HALF_BITS = N.bit_length() // 2 + 1  # signed GLV halves fit in ~129 bits

# Scalars the spec names, plus structural ones.
SPEC_SCALARS = [0, 1, N - 1, N, N + 1, LAMBDA, N - LAMBDA,
                LAMBDA * LAMBDA % N, 2, 3, (N - 1) // 2, 2**128, 2**255, 2**256 - 1]


def _point(seed: int) -> tuple[int, int]:
    point = ref.scalar_mult(seed)
    assert point is not None
    return point


POINTS = [curve.G, ref.negate(curve.G), _point(2), _point(0xBEEF), _point(123456789)]


# --- GLV decomposition ----------------------------------------------------------------------------

@pytest.mark.parametrize("k", SPEC_SCALARS)
def test_glv_reconstruction_modulo_n(k: int) -> None:
    k1, k2 = glv_decompose(k)
    assert (k1 + k2 * LAMBDA - k) % N == 0            # k == k1 + k2*lambda (mod N)


@pytest.mark.parametrize("k", SPEC_SCALARS)
def test_glv_signed_decomposition_bounds(k: int) -> None:
    k1, k2 = glv_decompose(k)
    assert abs(k1).bit_length() <= HALF_BITS          # both halves ~half the width of N
    assert abs(k2).bit_length() <= HALF_BITS


def test_phi_is_lambda_times_P_and_drives_the_decomposition() -> None:
    for point in POINTS:
        phi = (BETA * point[0] % P, point[1])
        assert phi == ref.scalar_mult(LAMBDA, point)  # phi(P) = (BETA*x, y) = lambda*P
        assert ref.is_on_curve(phi)


@pytest.mark.parametrize("k", SPEC_SCALARS)
def test_kP_equals_k1P_plus_k2_phiP(k: int) -> None:
    # The identity the optimization rests on: k*P == k1*P + k2*phi(P).
    k1, k2 = glv_decompose(k)
    for point in POINTS:
        phi = (BETA * point[0] % P, point[1])
        combined = point_add_affine(ref.scalar_mult(k1 % N, point), ref.scalar_mult(k2 % N, phi))
        assert combined == ref.scalar_mult(k % N, point)


@given(st.integers(0, N - 1))
@FAST
def test_glv_reconstruction_and_bounds_random(k: int) -> None:
    k1, k2 = glv_decompose(k)
    assert (k1 + k2 * LAMBDA - k) % N == 0
    assert abs(k1).bit_length() <= HALF_BITS
    assert abs(k2).bit_length() <= HALF_BITS


def test_lambda_edge_cases_produce_small_or_zero_halves() -> None:
    # k == lambda -> (0, 1); k == 1 -> (1, 0); these drive the degenerate GLV branches.
    assert glv_decompose(LAMBDA) == (0, 1)
    assert glv_decompose(1) == (1, 0)
    assert glv_decompose(0) == (0, 0)
    k1, k2 = glv_decompose(N - LAMBDA)
    assert (k1 + k2 * LAMBDA + LAMBDA) % N == 0


# --- wNAF recoding ---------------------------------------------------------------------------------

@pytest.mark.parametrize("w", [2, 3, 4, 5])
def test_wnaf_digits_reconstruct_the_scalar(w: int) -> None:
    rng = random.Random(w)
    for k in [0, 1, 2, 2**128, N - 1] + [rng.randrange(1, 2**130) for _ in range(100)]:
        digits = wnaf_digits(k, w)
        assert sum(d << i for i, d in enumerate(digits)) == k


@pytest.mark.parametrize("w", [2, 3, 4, 5])
def test_wnaf_digits_are_non_adjacent_odd_and_bounded(w: int) -> None:
    rng = random.Random(w + 10)
    limit = 1 << (w - 1)
    for k in [1, 2**127, N - 1] + [rng.randrange(1, 2**130) for _ in range(100)]:
        digits = wnaf_digits(k, w)
        for i, d in enumerate(digits):
            if d:
                assert d % 2 == 1 and -limit < d < limit          # nonzero digits odd, in range
                assert all(digits[i + j] == 0 for j in range(1, w) if i + j < len(digits))  # w-1 zeros follow
        assert not digits or digits[-1] != 0                      # no leading zero digit


def test_wnaf_zero_is_empty() -> None:
    assert wnaf_digits(0, _GLV_WNAF_WINDOW) == ()


# --- GLV+wNAF multiplication against all oracles --------------------------------------------------

@pytest.mark.parametrize("k", SPEC_SCALARS)
def test_glv_wnaf_matches_reference_for_spec_scalars(k: int) -> None:
    for point in POINTS:
        expected = ref.scalar_mult(k % N, point) if k % N else None
        assert scalar_mult(k, point, backend=OPT) == expected
        if k % N:  # the low-level routine's contract: reduced, non-zero scalar
            assert _scalar_mult_glv_wnaf(k % N, point) == expected


def test_glv_wnaf_matches_every_contract_backend_on_random_inputs() -> None:
    rng = random.Random(0x6_12_f)
    backends = ["python", "python-reference", "python-glv"]
    for name in ("coincurve", "fastecdsa"):
        if curve._backend_installed(name):
            backends.append(name)
    for _ in range(80):
        k = rng.randrange(1, N)
        point = _point(rng.randrange(1, N))
        optimized = scalar_mult(k, point, backend=OPT)
        for backend in backends:
            assert scalar_mult(k, point, backend=backend) == optimized


def test_auto_without_native_backend_uses_glv_wnaf_for_arbitrary_points(monkeypatch) -> None:
    monkeypatch.setattr(curve, "find_spec", lambda _name: None)
    curve._INSTALLED_BACKENDS.clear()
    try:
        rng = random.Random(1)
        for _ in range(20):
            k = rng.randrange(1, N)
            point = _point(rng.randrange(1, N))
            assert scalar_mult(k, point) == _scalar_mult_glv_wnaf(k, point)
    finally:
        curve._INSTALLED_BACKENDS.clear()


@given(st.integers(1, N - 1), st.integers(1, N - 1))
@FAST
def test_glv_wnaf_matches_reference_random(k: int, seed: int) -> None:
    point = ref.scalar_mult(seed)
    assert _scalar_mult_glv_wnaf(k, point) == ref.scalar_mult(k, point)


def test_glv_wnaf_handles_infinity_and_cancellation() -> None:
    point = _point(42)
    # k and N-k give mutually inverse points; their sum is infinity.
    for k in (1, 2, 12345, LAMBDA):
        assert point_add_affine(scalar_mult(k, point, backend=OPT),
                                scalar_mult(N - k, point, backend=OPT)) is None
    assert scalar_mult(N, point, backend=OPT) is None
    assert scalar_mult(0, point, backend=OPT) is None


def test_glv_wnaf_is_additive() -> None:
    rng = random.Random(0xADD)
    point = _point(7)
    for _ in range(60):
        a, b = rng.randrange(1, N), rng.randrange(1, N)
        assert point_add_affine(scalar_mult(a, point, backend=OPT),
                                scalar_mult(b, point, backend=OPT)) == scalar_mult((a + b) % N, point, backend=OPT)


def test_validation_framework_is_clean() -> None:
    from keylab.ec import validation

    validation.assert_no_mismatches(validation.validate_all())
