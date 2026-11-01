"""Multi-scalar multiplication foundation: sum(k_i * P_i) (M2.6).

`multi_scalar_mult` is validated against the naive reference
(`keylab.ec.reference.multi_scalar_mult`) and every contract backend, over the
MSM corner cases the spec names (empty, singleton, duplicate points/scalars,
zero scalars, infinity, cancellation) plus random and Hypothesis inputs.
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
METHODS = list(curve.MSM_METHODS)


def _point(seed: int):
    return ref.scalar_mult(seed)


POINTS = [G, ref.negate(G), ref.double(G), _point(777), _point(0xC0FFEE), _point(12345678)]


def _naive(pairs):
    total = None
    for scalar, point in pairs:
        total = point_add_affine(total, scalar_mult(scalar % N, point))
    return total


@pytest.mark.parametrize("method", METHODS)
def test_empty_input_is_infinity(method: str) -> None:
    assert multi_scalar_mult([], method=method) is None


@pytest.mark.parametrize("method", METHODS)
def test_singleton_equals_scalar_mult(method: str) -> None:
    for k in (1, 2, 12345, N - 1):
        for point in POINTS:
            assert multi_scalar_mult([(k, point)], method=method) == scalar_mult(k, point)


@pytest.mark.parametrize("method", METHODS)
def test_duplicate_points(method: str) -> None:
    pairs = [(3, G), (5, G), (7, G)]
    assert multi_scalar_mult(pairs, method=method) == scalar_mult(15, G)


@pytest.mark.parametrize("method", METHODS)
def test_duplicate_scalars(method: str) -> None:
    pairs = [(9, G), (9, ref.double(G)), (9, _point(42))]
    assert multi_scalar_mult(pairs, method=method) == ref.multi_scalar_mult(pairs)


@pytest.mark.parametrize("method", METHODS)
def test_zero_scalars_contribute_nothing(method: str) -> None:
    pairs = [(0, G), (7, ref.double(G)), (0, _point(99))]
    assert multi_scalar_mult(pairs, method=method) == scalar_mult(7, ref.double(G))
    assert multi_scalar_mult([(0, p) for p in POINTS], method=method) is None


@pytest.mark.parametrize("method", METHODS)
def test_infinity_inputs_are_skipped(method: str) -> None:
    assert multi_scalar_mult([(5, None), (7, G), (3, None)], method=method) == scalar_mult(7, G)
    assert multi_scalar_mult([(5, None), (0, None)], method=method) is None


@pytest.mark.parametrize("method", METHODS)
def test_cancellation_to_infinity(method: str) -> None:
    assert multi_scalar_mult([(12345, G), (N - 12345, G)], method=method) is None
    assert multi_scalar_mult([(8, G), (8, ref.negate(G))], method=method) is None
    assert multi_scalar_mult([(1, G), (1, ref.double(G)), (1, ref.negate(ref.scalar_mult(3)))],
                             method=method) is None  # G + 2G + (-3G)


@pytest.mark.parametrize("method", METHODS)
def test_scalars_reduced_modulo_n(method: str) -> None:
    pairs = [(N + 5, G), (2 * N + 1, ref.double(G))]
    assert multi_scalar_mult(pairs, method=method) == ref.multi_scalar_mult([(5, G), (1, ref.double(G))])


# --- size sweep / boundary cases ------------------------------------------------------------------

@pytest.mark.parametrize("n", [1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 128])
def test_size_sweep_matches_reference(n: int) -> None:
    rng = random.Random(1000 + n)
    pairs = [(rng.randrange(0, N), _point(rng.randrange(1, N))) for _ in range(n)]
    expected = ref.multi_scalar_mult(pairs)
    for method in METHODS:
        assert multi_scalar_mult(pairs, method=method) == expected


# --- differential: reference / naive / optimized / native ----------------------------------------

def test_matches_all_oracles_on_random_batches() -> None:
    rng = random.Random(0x6)
    native = [b for b in ("coincurve", "fastecdsa") if curve._backend_installed(b)]
    for _ in range(40):
        n = rng.randrange(0, 20)
        pairs = [(rng.randrange(0, N), _point(rng.randrange(1, N))) for _ in range(n)]
        expected = ref.multi_scalar_mult(pairs)
        assert _naive(pairs) == expected
        for method in METHODS:
            assert multi_scalar_mult(pairs, method=method) == expected
            for backend in native:
                assert multi_scalar_mult(pairs, method=method, backend=backend) == expected


def test_validation_framework_reports_no_msm_mismatches() -> None:
    validation.assert_no_mismatches(validation.diff_msm())


def test_framework_detects_a_broken_msm(monkeypatch) -> None:
    monkeypatch.setattr(curve, "multi_scalar_mult",
                        lambda pairs, **kw: scalar_mult(2, G) if list(pairs) else None)
    assert validation.diff_msm()


# --- malformed input ------------------------------------------------------------------------------

def test_rejects_bad_method() -> None:
    with pytest.raises(ValueError, match="method must be"):
        multi_scalar_mult([(1, G)], method="pippenger")


@pytest.mark.parametrize("bad", [[(1,)], [(1, G, 2)], [(-1, G)], [(1.0, G)], [("k", G)], [5]])
def test_rejects_malformed_pairs(bad) -> None:
    with pytest.raises(ValueError):
        multi_scalar_mult(bad)


def test_accepts_any_iterable() -> None:
    pairs = ((k, G) for k in (1, 2, 3))  # a generator, not a list
    assert multi_scalar_mult(pairs) == scalar_mult(6, G)


# --- Hypothesis -----------------------------------------------------------------------------------

@given(st.lists(st.tuples(st.integers(0, N - 1), st.integers(1, N - 1)), max_size=24))
@FAST
def test_random_batches_match_reference(raw: list[tuple[int, int]]) -> None:
    pairs = [(k, _point(seed)) for k, seed in raw]
    expected = ref.multi_scalar_mult(pairs)
    assert multi_scalar_mult(pairs) == expected
    assert multi_scalar_mult(pairs, method="naive") == expected
