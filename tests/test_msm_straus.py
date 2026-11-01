"""Straus/Shamir MSM method: identical to the naive reference, faster for n >= 2 (M2.7).

`multi_scalar_mult(..., method="straus")` shares one doubling chain across all
terms via interleaved GLV+wNAF. It must equal `keylab.ec.reference`, the naive
MSM, and every scalar-mult backend on every input.
"""

from __future__ import annotations

import random

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from keylab.ec import reference as ref
from keylab.ec import secp256k1 as curve
from keylab.ec import validation
from keylab.ec.secp256k1 import G, N, multi_scalar_mult, point_add_affine, scalar_mult

FAST = settings(max_examples=40, deadline=None)
STRAUS = {"method": "straus"}


def _point(seed: int):
    return ref.scalar_mult(seed)


ARBITRARY = [_point(s) for s in (2, 3, 777, 0xC0FFEE, 12345678, 99)]


def _straus(pairs):
    return multi_scalar_mult(pairs, method="straus")


def _expected(pairs):
    return ref.multi_scalar_mult([(k % N, p) for k, p in pairs])


# --- required corner cases --------------------------------------------------------------------

def test_empty_input() -> None:
    assert _straus([]) is None


def test_singleton_equals_scalar_mult() -> None:
    for k in (1, 2, 12345, N - 1):
        for point in (G, *ARBITRARY):
            assert _straus([(k, point)]) == scalar_mult(k, point)


def test_duplicate_points() -> None:
    assert _straus([(3, G), (5, G), (7, G)]) == scalar_mult(15, G)
    q = _point(55)
    assert _straus([(10, q), (20, q), (30, q)]) == scalar_mult(60, q)


def test_duplicate_scalars() -> None:
    pairs = [(9, G), (9, _point(2)), (9, _point(3))]
    assert _straus(pairs) == _expected(pairs)


def test_zero_scalars() -> None:
    assert _straus([(0, G), (7, _point(2)), (0, _point(3))]) == scalar_mult(7, _point(2))
    assert _straus([(0, p) for p in (G, *ARBITRARY)]) is None


def test_infinity_inputs() -> None:
    assert _straus([(5, None), (7, G), (0, None)]) == scalar_mult(7, G)
    assert _straus([(5, None), (0, None)]) is None


def test_cancellation_to_infinity() -> None:
    assert _straus([(12345, G), (N - 12345, G)]) is None
    assert _straus([(8, G), (8, ref.negate(G))]) is None
    assert _straus([(1, G), (1, ref.double(G)), (1, ref.negate(ref.scalar_mult(3)))]) is None


def test_generator_only_inputs() -> None:
    pairs = [(3, G), (0, G), (N - 1, G), (2**128, G)]
    assert _straus(pairs) == _expected(pairs)


def test_mixed_generator_and_arbitrary_points() -> None:
    pairs = [(5, G), (7, _point(10)), (9, G), (11, _point(20)), (13, ref.negate(G))]
    assert _straus(pairs) == _expected(pairs)


def test_scalars_reduced_modulo_n() -> None:
    pairs = [(N + 5, G), (2 * N + 1, _point(2))]
    assert _straus(pairs) == _expected(pairs)


# --- window / size boundary sweep -------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128])
def test_size_sweep_matches_reference_and_naive(n: int) -> None:
    rng = random.Random(2000 + n)
    pairs = [(rng.randrange(0, N), _point(rng.randrange(1, N))) for _ in range(n)]
    expected = ref.multi_scalar_mult(pairs)
    assert multi_scalar_mult(pairs, method="straus") == expected
    assert multi_scalar_mult(pairs, method="naive") == expected
    assert multi_scalar_mult(pairs, method="auto") == expected


# --- differential: all oracles ----------------------------------------------------------------

def test_matches_all_oracles() -> None:
    rng = random.Random(0x57_6a_5)
    native = [b for b in ("coincurve", "fastecdsa") if curve._backend_installed(b)]
    for _ in range(40):
        n = rng.randrange(0, 24)
        pairs = [(rng.randrange(0, N), _point(rng.randrange(1, N))) for _ in range(n)]
        expected = ref.multi_scalar_mult(pairs)
        assert multi_scalar_mult(pairs, method="straus") == expected
        assert multi_scalar_mult(pairs, method="naive") == expected
        for backend in native:
            assert multi_scalar_mult(pairs, method="naive", backend=backend) == expected


def test_diff_msm_covers_straus() -> None:
    assert "straus" in curve.MSM_METHODS
    validation.assert_no_mismatches(validation.diff_msm(methods=["straus"]))
    validation.assert_no_mismatches(validation.diff_msm())


def test_framework_detects_a_broken_straus(monkeypatch) -> None:
    real = curve._msm_straus
    monkeypatch.setattr(curve, "_msm_straus", lambda pairs: ref.double(real(pairs)) if pairs else None)
    assert validation.diff_msm(methods=["straus"])


# --- auto dispatch ----------------------------------------------------------------------------

def test_auto_uses_straus_for_multi_term_without_native(monkeypatch) -> None:
    monkeypatch.setattr(curve, "find_spec", lambda _name: None)
    curve._INSTALLED_BACKENDS.clear()
    try:
        pairs = [(3, G), (5, _point(2))]
        assert curve._msm_uses_native("auto") is False
        assert multi_scalar_mult(pairs, method="auto") == _straus(pairs)
    finally:
        curve._INSTALLED_BACKENDS.clear()


def test_auto_uses_naive_for_single_term() -> None:
    assert multi_scalar_mult([(12345, _point(2))], method="auto") == scalar_mult(12345, _point(2))


def test_rejects_bad_method_and_input() -> None:
    with pytest.raises(ValueError, match="method must be"):
        multi_scalar_mult([(1, G)], method="pippenger")
    with pytest.raises(ValueError):
        multi_scalar_mult([(-1, G)], method="straus")


# --- Hypothesis ---------------------------------------------------------------------------------

@given(st.lists(st.tuples(st.integers(0, N - 1), st.integers(1, N - 1)), max_size=24))
@FAST
def test_random_batches_match_reference(raw: list[tuple[int, int]]) -> None:
    pairs = [(k, _point(seed)) for k, seed in raw]
    expected = ref.multi_scalar_mult(pairs)
    assert multi_scalar_mult(pairs, method="straus") == expected
    assert multi_scalar_mult(pairs, method="auto") == expected


@given(st.lists(st.integers(0, N - 1), min_size=1, max_size=12))
@FAST
def test_straus_additivity(scalars: list[int]) -> None:
    point = _point(7)
    pairs = [(k, point) for k in scalars]
    assert multi_scalar_mult(pairs, method="straus") == scalar_mult(sum(scalars) % N, point)
    naive_sum = None
    for k in scalars:
        naive_sum = point_add_affine(naive_sum, scalar_mult(k, point))
    assert multi_scalar_mult(pairs, method="straus") == naive_sum
