"""Pippenger bucket-method MSM: identical to the naive reference, faster for large n (M2.8).

`multi_scalar_mult(..., method="pippenger")` must equal `keylab.ec.reference`,
the naive and Straus methods, and the native backends, on every input -- with
extra attention to bucket and window boundaries and large batches.
"""

from __future__ import annotations

import random

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from keylab.ec import reference as ref
from keylab.ec import secp256k1 as curve
from keylab.ec import validation
from keylab.ec.secp256k1 import G, N, multi_scalar_mult, scalar_mult

FAST = settings(max_examples=30, deadline=None)


def _point(seed: int):
    return ref.scalar_mult(seed)


def _pip(pairs, **kw):
    return multi_scalar_mult(pairs, method="pippenger", **kw)


def _expected(pairs):
    return ref.multi_scalar_mult([(k % N, p) for k, p in pairs])


# --- required corner cases --------------------------------------------------------------------

def test_empty_input() -> None:
    assert _pip([]) is None


def test_singleton_equals_scalar_mult() -> None:
    for k in (1, 2, 12345, N - 1):
        for point in (G, _point(2), _point(777)):
            assert _pip([(k, point)]) == scalar_mult(k, point)


def test_duplicate_points() -> None:
    assert _pip([(3, G), (5, G), (7, G)]) == scalar_mult(15, G)


def test_duplicate_scalars() -> None:
    pairs = [(9, G), (9, _point(2)), (9, _point(3))]
    assert _pip(pairs) == _expected(pairs)


def test_zero_scalars() -> None:
    assert _pip([(0, G), (7, _point(2)), (0, _point(3))]) == scalar_mult(7, _point(2))
    assert _pip([(0, G), (0, _point(2))]) is None


def test_infinity_inputs() -> None:
    assert _pip([(5, None), (7, G), (0, None)]) == scalar_mult(7, G)
    assert _pip([(5, None), (0, None)]) is None


def test_cancellation_to_infinity() -> None:
    assert _pip([(12345, G), (N - 12345, G)]) is None
    assert _pip([(8, G), (8, ref.negate(G))]) is None


def test_scalars_reduced_modulo_n() -> None:
    pairs = [(N + 5, G), (2 * N + 1, _point(2))]
    assert _pip(pairs) == _expected(pairs)


# --- bucket / window boundaries -----------------------------------------------------------------

@pytest.mark.parametrize("c", [2, 3, 4, 5, 6, 8])
def test_every_window_width_matches_reference(c: int) -> None:
    rng = random.Random(400 + c)
    pairs = [(rng.randrange(0, N), _point(rng.randrange(1, N))) for _ in range(40)]
    assert curve._msm_pippenger(curve._validated_pairs(pairs), window=c) == ref.multi_scalar_mult(pairs)


def test_scalar_digit_hits_top_and_edge_buckets() -> None:
    # Scalars that are exactly a single window digit (1, max bucket) at various positions,
    # and the top partial window of a 256-bit-ceiling scalar.
    for c in (3, 4, 5):
        maxd = (1 << c) - 1
        windows = (N.bit_length() + c - 1) // c
        pairs = []
        for w in range(windows):
            for d in (1, maxd):
                k = (d << (w * c)) % N
                if k:
                    pairs.append((k, G))
        assert curve._msm_pippenger(curve._validated_pairs(pairs), window=c) == ref.multi_scalar_mult(pairs)


def test_all_terms_in_one_bucket() -> None:
    # Every term shares the same scalar -> each window digit is identical (one hot bucket).
    pairs = [(7, _point(i + 1)) for i in range(20)]
    assert curve._msm_pippenger(curve._validated_pairs(pairs), window=4) == ref.multi_scalar_mult(pairs)


def test_bucket_summing_to_infinity() -> None:
    # Two points in the same bucket that cancel: digit d on P and on -P.
    d = 5
    pairs = [(d, G), (d, ref.negate(G)), (3, _point(9))]
    assert curve._msm_pippenger(curve._validated_pairs(pairs), window=4) == scalar_mult(3, _point(9))


def test_window_count_covers_full_scalar_range() -> None:
    # Near-N scalars exercise the top window; must still match.
    pairs = [(N - 1, G), (N - 2, _point(2)), (2**255, _point(3)), ((1 << 252) | 1, _point(4))]
    for c in (2, 5, 8):
        assert curve._msm_pippenger(curve._validated_pairs(pairs), window=c) == ref.multi_scalar_mult(pairs)


# --- size sweep incl. large batches, vs reference + straus + naive -------------------------------

@pytest.mark.parametrize("n", [1, 2, 4, 8, 16, 32, 64, 127, 128, 129, 200, 256, 384, 512])
def test_size_sweep_matches_reference_naive_straus(n: int) -> None:
    rng = random.Random(5000 + n)
    pairs = [(rng.randrange(0, N), _point(rng.randrange(1, N))) for _ in range(n)]
    expected = ref.multi_scalar_mult(pairs)
    assert multi_scalar_mult(pairs, method="pippenger") == expected
    assert multi_scalar_mult(pairs, method="straus") == expected
    assert multi_scalar_mult(pairs, method="naive") == expected
    assert multi_scalar_mult(pairs, method="auto") == expected


def test_large_batch() -> None:
    rng = random.Random(2024)
    pairs = [(rng.randrange(1, N), _point(rng.randrange(1, N))) for _ in range(600)]
    assert multi_scalar_mult(pairs, method="pippenger") == ref.multi_scalar_mult(pairs)


# --- differential / framework / auto-dispatch ----------------------------------------------------

def test_matches_all_oracles() -> None:
    rng = random.Random(0x717)
    native = [b for b in ("coincurve", "fastecdsa") if curve._backend_installed(b)]
    for n in (0, 1, 3, 17, 50, 130):
        pairs = [(rng.randrange(0, N), _point(rng.randrange(1, N))) for _ in range(n)]
        expected = ref.multi_scalar_mult(pairs)
        assert multi_scalar_mult(pairs, method="pippenger") == expected
        assert multi_scalar_mult(pairs, method="straus") == expected
        for backend in native:
            assert multi_scalar_mult(pairs, method="naive", backend=backend) == expected


def test_diff_msm_covers_pippenger() -> None:
    assert "pippenger" in curve.MSM_METHODS
    validation.assert_no_mismatches(validation.diff_msm(methods=["pippenger"]))
    validation.assert_no_mismatches(validation.diff_msm())


def test_framework_detects_a_broken_pippenger(monkeypatch) -> None:
    real = curve._msm_pippenger
    monkeypatch.setattr(curve, "_msm_pippenger", lambda pairs, window=None: ref.double(real(pairs)) if pairs else None)
    assert validation.diff_msm(methods=["pippenger"])


def test_auto_uses_pippenger_for_large_batches_without_native(monkeypatch) -> None:
    monkeypatch.setattr(curve, "find_spec", lambda _name: None)
    curve._INSTALLED_BACKENDS.clear()
    try:
        rng = random.Random(3)
        big = [(rng.randrange(1, N), _point(rng.randrange(1, N))) for _ in range(curve._PIPPENGER_MIN_TERMS)]
        small = big[:4]
        assert multi_scalar_mult(big, method="auto") == _pip(big)
        assert multi_scalar_mult(small, method="auto") == multi_scalar_mult(small, method="straus")
    finally:
        curve._INSTALLED_BACKENDS.clear()


def test_window_heuristic_is_monotone_and_bounded() -> None:
    assert curve._pippenger_window(1) >= 2
    widths = [curve._pippenger_window(n) for n in (16, 32, 64, 128, 256, 512)]
    assert widths == sorted(widths) and widths == [2, 3, 4, 5, 6, 7]


# --- Hypothesis -----------------------------------------------------------------------------------

@given(st.lists(st.tuples(st.integers(0, N - 1), st.integers(1, N - 1)), max_size=40))
@FAST
def test_random_batches_match_reference(raw: list[tuple[int, int]]) -> None:
    pairs = [(k, _point(seed)) for k, seed in raw]
    assert multi_scalar_mult(pairs, method="pippenger") == ref.multi_scalar_mult(pairs)
