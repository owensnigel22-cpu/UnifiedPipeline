"""Every implementation matches the frozen reference (docs/PERFORMANCE_VALIDATION.md).

These tests are the acceptance gate for M2 optimizations: an optimized path
that disagrees with keylab.ec.reference on any input fails here.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from keylab.ec import reference as ref
from keylab.ec import secp256k1, validation
from keylab.ec.sec1 import parse_sec1, serialize_sec1, serialize_uncompressed, serialize_xonly

FAST = settings(max_examples=25, deadline=None)
nonzero = st.integers(min_value=1, max_value=secp256k1.N - 1)
any_scalar = st.one_of(st.integers(min_value=0, max_value=2**300), st.sampled_from(validation.EDGE_SCALARS))
field = st.integers(min_value=1, max_value=secp256k1.P - 1)


# --- the contract -----------------------------------------------------------------------------

def test_contract_backends_are_selectable_scalar_mult_backends() -> None:
    for name in (*validation.CONTRACT_BACKENDS, *validation.PYTHON_STRATEGIES):
        assert name in secp256k1.SCALAR_MULT_BACKENDS
    with pytest.raises(ValueError, match="python-reference"):
        secp256k1.scalar_mult(1, backend="no-such-backend")


def test_python_optimized_is_exactly_auto_without_native_backends(monkeypatch) -> None:
    monkeypatch.setattr(secp256k1, "find_spec", lambda _name: None)
    for scalar in (1, 7, 2**200 + 3, secp256k1.N - 1):
        for point in validation.edge_points()[:3]:
            assert (secp256k1.scalar_mult(scalar, point)
                    == secp256k1.scalar_mult(scalar, point, backend="python-optimized"))


def test_available_backends_only_lists_installed_native_libraries(monkeypatch) -> None:
    monkeypatch.setattr(secp256k1, "find_spec", lambda _name: None)
    assert validation.available_backends(include_strategies=False) == ("python-reference", "python-optimized")


# --- edge-case matrices (the deterministic gate) ------------------------------------------------

def test_scalar_multiplication_matches_reference_for_every_backend_on_edge_inputs() -> None:
    validation.assert_no_mismatches(validation.diff_scalar_mult())


def test_addition_doubling_negation_and_jacobian_conversion_match_reference() -> None:
    validation.assert_no_mismatches(validation.diff_group_operations())


def test_serialization_and_parsing_match_reference() -> None:
    validation.assert_no_mismatches(validation.diff_serialization())


def test_point_at_infinity_is_handled_identically_everywhere() -> None:
    validation.assert_no_mismatches(validation.diff_infinity())


def test_edge_inputs_cover_the_documented_boundaries() -> None:
    scalars = set(validation.EDGE_SCALARS)
    n = secp256k1.N
    assert {0, 1, n - 1, n, n + 1, 2 * n, (n + 1) // 2, secp256k1.LAMBDA, 2**256} <= scalars
    assert any(s > 2**256 for s in scalars)
    points = validation.edge_points()
    assert secp256k1.G in points and ref.negate(secp256k1.G) in points
    assert all(ref.is_on_curve(p) for p in points)


# --- the framework detects broken implementations -----------------------------------------------

def test_a_wrong_scalar_multiplication_is_reported(monkeypatch) -> None:
    original = secp256k1._scalar_mult_pure_python

    def off_by_one(scalar: int, point):
        return original(scalar + 1 if scalar == 5 else scalar, point)

    monkeypatch.setattr(secp256k1, "_scalar_mult_pure_python", off_by_one)
    mismatches = validation.diff_scalar_mult(scalars=(4, 5, 6), backends=("python-optimized",))
    assert [m.inputs.split(",")[0] for m in mismatches] == ["k=0x5"] * len(validation.edge_points())
    with pytest.raises(AssertionError, match="mismatch"):
        validation.assert_no_mismatches(mismatches)


def test_a_wrong_jacobian_addition_is_reported(monkeypatch) -> None:
    original = secp256k1.point_add
    monkeypatch.setattr(secp256k1, "point_add",
                        lambda left, right: secp256k1.point_double(original(left, right)))
    assert any(m.operation == "point_add(jacobian)" for m in validation.diff_group_operations())


def test_a_wrong_encoding_is_reported(monkeypatch) -> None:
    monkeypatch.setattr(secp256k1, "compress_pubkey", lambda point: b"\x02" + point[0].to_bytes(32, "big"))
    assert any(m.operation == "compress_pubkey" for m in validation.diff_serialization())


# --- Hypothesis: random inputs against the reference --------------------------------------------

@FAST
@given(any_scalar, nonzero)
def test_random_scalars_and_points_match_reference_for_every_backend(scalar: int, seed: int) -> None:
    point = ref.scalar_mult(seed)
    validation.assert_no_mismatches(validation.diff_scalar_mult([scalar], [point]))


@FAST
@given(nonzero, nonzero, field, field)
def test_random_jacobian_representations_add_and_double_like_the_reference(
    a: int, b: int, z1: int, z2: int
) -> None:
    left, right = ref.scalar_mult(a), ref.scalar_mult(b)
    assert left is not None and right is not None
    jl = (left[0] * z1 * z1 % secp256k1.P, left[1] * z1**3 % secp256k1.P, z1)
    jr = (right[0] * z2 * z2 % secp256k1.P, right[1] * z2**3 % secp256k1.P, z2)
    assert secp256k1._to_affine(jl) == left
    assert secp256k1._to_affine(secp256k1.point_add(jl, jr)) == ref.add(left, right)
    assert secp256k1._to_affine(secp256k1.point_double(jl)) == ref.double(left)
    assert secp256k1._to_affine(secp256k1._point_add_mixed(jl, right)) == ref.add(left, right)
    assert secp256k1.point_add_affine(left, right) == ref.add(left, right)


@FAST
@given(nonzero)
def test_random_points_serialize_and_parse_like_the_reference(seed: int) -> None:
    point = ref.scalar_mult(seed)
    assert serialize_sec1(point) == ref.encode_compressed(point)
    assert serialize_uncompressed(point) == ref.encode_uncompressed(point)
    assert serialize_xonly(point) == ref.encode_xonly(point)
    assert parse_sec1(ref.encode_compressed(point)) == point
    assert parse_sec1(ref.encode_uncompressed(point)) == point
