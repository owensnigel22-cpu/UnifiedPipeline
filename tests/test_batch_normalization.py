"""Batch normalization (Montgomery's trick) matches per-point and reference results exactly."""

from __future__ import annotations

import random

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from keylab import advanced_suite
from keylab.ec import reference as ref
from keylab.ec import secp256k1, validation
from keylab.ec.secp256k1 import N, P, batch_inverse, batch_to_affine

FAST = settings(max_examples=30, deadline=None)


def _jacobian(point: tuple[int, int], z: int) -> tuple[int, int, int]:
    return point[0] * z * z % P, point[1] * z**3 % P, z


def _points(count: int, seed: int) -> list[tuple[int, int]]:
    rng = random.Random(seed)
    points = []
    for _ in range(count):
        point = secp256k1.scalar_mult(rng.randrange(1, N), backend="python")
        assert point is not None
        points.append(point)
    return points


@pytest.fixture
def inversions(monkeypatch) -> list[int]:
    """Record every modular inversion performed by keylab.ec.secp256k1."""
    calls: list[int] = []
    real = secp256k1.mod_inverse_builtin

    def counting(value: int, modulus: int) -> int:
        calls.append(modulus)
        return real(value, modulus)

    monkeypatch.setattr(secp256k1, "mod_inverse_builtin", counting)
    return calls


# --- batch_inverse ------------------------------------------------------------------------------

def test_batch_inverse_of_nothing_is_nothing(inversions) -> None:
    assert batch_inverse([]) == []
    assert inversions == []


def test_batch_inverse_matches_pow_for_both_moduli() -> None:
    rng = random.Random(3)
    for modulus in (P, N):
        values = [rng.randrange(1, modulus) for _ in range(50)] + [1, modulus - 1, modulus + 2, -5]
        assert batch_inverse(values, modulus) == [pow(v, -1, modulus) for v in values]


def test_batch_inverse_uses_one_inversion_for_any_batch_size(inversions) -> None:
    batch_inverse(list(range(1, 501)))
    assert inversions == [P]


@pytest.mark.parametrize("values", [[3, 0, 5], [P], [2 * P, 1], [1, 2, -P]])
def test_batch_inverse_rejects_values_without_an_inverse(values: list[int]) -> None:
    with pytest.raises(ValueError, match="has no inverse"):
        batch_inverse(values)


@pytest.mark.parametrize("values", [[1, 2.0], [None], [True]])
def test_batch_inverse_rejects_non_integers(values: list[object]) -> None:
    with pytest.raises(ValueError, match="must be an int"):
        batch_inverse(values)  # type: ignore[arg-type]


# --- batch_to_affine: required cases ------------------------------------------------------------

def test_empty_batch(inversions) -> None:
    assert batch_to_affine([]) == []
    assert batch_to_affine(iter(())) == []
    assert inversions == []


@pytest.mark.parametrize("z", [1, 2, P - 1, 0xDEADBEEF])
def test_single_element_batch_matches_to_affine_and_reference(z: int) -> None:
    point = _points(1, z)[0]
    jacobian = _jacobian(point, z)
    assert batch_to_affine([jacobian]) == [secp256k1._to_affine(jacobian)] == [point]
    assert ref.is_on_curve(point)


def test_large_batch_matches_per_point_and_reference(inversions) -> None:
    points = _points(1000, 11)
    rng = random.Random(12)
    batch = [_jacobian(point, rng.randrange(1, P)) for point in points]
    del inversions[:]
    result = batch_to_affine(batch)
    assert inversions == [P]  # one inversion for the whole batch
    assert result == points
    assert result == [secp256k1._to_affine(point) for point in batch]


def test_points_at_infinity_keep_their_positions(inversions) -> None:
    point = _points(1, 5)[0]
    batch = [None, _jacobian(point, 9), (1, 2, 0), None, (3, 4, P), (5, 6, 2 * P), point]
    assert batch_to_affine(batch) == [None, point, None, None, None, None, point]
    del inversions[:]
    assert batch_to_affine([None, (1, 1, 0), (2, 2, P)]) == [None, None, None]
    assert inversions == []  # nothing finite to invert


@pytest.mark.parametrize(
    "bad",
    [5, "point", [1, 2, 3], (1,), (1, 2, 3, 4), (1.0, 2, 3), (1, 2, None), (True, 2, 3), (1, "2")],
)
def test_malformed_points_are_rejected_with_their_index(bad: object) -> None:
    with pytest.raises(ValueError, match="malformed point at index 1"):
        batch_to_affine([None, bad])


def test_mixed_jacobian_and_affine_paths() -> None:
    a, b, c = _points(3, 21)
    ja, jb = secp256k1._to_jacobian(a), _jacobian(b, 77)
    produced = [
        secp256k1.point_add(ja, jb),          # Jacobian + Jacobian
        secp256k1._point_add_mixed(jb, c),    # Jacobian + affine
        secp256k1.point_double(jb),           # Jacobian doubling
        secp256k1._point_add_mixed(ja, ref.negate(a)),  # P + (-P): infinity
        c,                                    # already affine
        None,
    ]
    expected = [ref.add(a, b), ref.add(b, c), ref.double(b), None, c, None]
    assert batch_to_affine(produced) == expected
    assert [secp256k1._to_affine(p) if len(p) == 3 else p  # type: ignore[arg-type]
            for p in produced[:5]] == expected[:5]


def test_generator_table_is_built_with_one_inversion(inversions) -> None:
    secp256k1._generator_affine_window_table.cache_clear()
    table = secp256k1._generator_affine_window_table()
    assert inversions == [P]
    flat = [point for window in table for point in window[1:]]
    assert len(flat) == 960
    # Spot-check against the reference: window w, digit d is d * 16^w * G.
    for window, digit in ((0, 1), (0, 15), (1, 3), (31, 7), (63, 15)):
        assert table[window][digit] == ref.scalar_mult(digit * 16**window)
    secp256k1._generator_affine_window_table.cache_clear()


# --- framework, differential, and property tests -------------------------------------------------

def test_validation_framework_reports_no_batch_mismatches() -> None:
    validation.assert_no_mismatches(validation.diff_batch_normalization())


def test_validation_framework_detects_a_broken_batch_normalization(monkeypatch) -> None:
    real = secp256k1.batch_to_affine
    monkeypatch.setattr(secp256k1, "batch_to_affine", lambda pts: list(reversed(real(pts))))
    assert validation.diff_batch_normalization()


def test_matches_advanced_suite_batch_conversion() -> None:
    points = _points(40, 31)
    rng = random.Random(32)
    batch = [_jacobian(point, rng.randrange(1, P)) for point in points]
    assert batch_to_affine(batch) == advanced_suite.batch_jacobian_to_affine(batch) == points
    values = [rng.randrange(1, P) for _ in range(40)]
    assert batch_inverse(values) == advanced_suite.batch_inv(values)


jacobian_entries = st.one_of(
    st.tuples(st.integers(1, N - 1), st.integers(1, P - 1)),   # finite point k*G with Z = z
    st.just("infinity-none"),
    st.just("infinity-z0"),
    st.integers(1, N - 1),                                      # affine point k*G
)


@FAST
@given(st.lists(jacobian_entries, max_size=12))
def test_random_mixed_batches_match_the_reference(entries: list[object]) -> None:
    batch: list[object] = []
    expected: list[tuple[int, int] | None] = []
    for entry in entries:
        if entry == "infinity-none":
            batch.append(None)
            expected.append(None)
        elif entry == "infinity-z0":
            batch.append((7, 9, 0))
            expected.append(None)
        elif isinstance(entry, int):
            point = ref.scalar_mult(entry)
            batch.append(point)
            expected.append(point)
        else:
            scalar, z = entry  # type: ignore[misc]
            point = ref.scalar_mult(scalar)
            assert point is not None
            batch.append(_jacobian(point, z))
            expected.append(point)
    assert batch_to_affine(batch) == expected


@FAST
@given(st.lists(st.integers(1, P - 1), max_size=40))
def test_random_batch_inverses_match_pow(values: list[int]) -> None:
    assert batch_inverse(values) == [pow(v, -1, P) for v in values]
