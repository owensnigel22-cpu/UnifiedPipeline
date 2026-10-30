"""Hypothesis property tests for secp256k1 group laws and encodings."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from keylab.ec.sec1 import parse_sec1, serialize_sec1, serialize_xonly
from keylab.ec.secp256k1 import (
    G,
    N,
    P,
    _to_affine,
    _to_jacobian,
    has_even_y,
    is_on_curve,
    lift_x,
    point_add,
    point_add_affine,
    point_double,
    point_negate_affine,
    scalar_mult,
    sqrt_mod_p,
)

scalars = st.integers(min_value=1, max_value=N - 1)
field_elements = st.integers(min_value=0, max_value=P - 1)
FAST = settings(max_examples=40, deadline=None)


def _mul(scalar: int) -> tuple[int, int] | None:
    return scalar_mult(scalar, G, backend="python")


@FAST
@given(scalars, scalars)
def test_scalar_multiplication_distributes_over_addition(k: int, m: int) -> None:
    # (k + m)G == kG + mG, including the wrap-around (k + m) mod N.
    assert _mul((k + m) % N) == point_add_affine(_mul(k), _mul(m))


@FAST
@given(scalars)
def test_group_order_annihilates_every_point(k: int) -> None:
    point = _mul(k)
    assert scalar_mult(N, point, backend="python") is None
    assert scalar_mult(N - 1, point, backend="python") == point_negate_affine(point)


def test_group_order_annihilates_generator() -> None:
    assert scalar_mult(N, G, backend="python") is None


@FAST
@given(scalars)
def test_doubling_equals_self_addition(k: int) -> None:
    point = _mul(k)
    assert point is not None
    doubled_jacobian = _to_affine(point_double(_to_jacobian(point)))
    assert doubled_jacobian == point_add_affine(point, point)
    assert _to_affine(point_add(_to_jacobian(point), _to_jacobian(point))) == doubled_jacobian
    assert scalar_mult(2, point, backend="python") == doubled_jacobian


@FAST
@given(scalars, scalars, scalars)
def test_point_addition_is_associative_and_commutative(a: int, b: int, c: int) -> None:
    pa, pb, pc = _mul(a), _mul(b), _mul(c)
    assert point_add_affine(pa, pb) == point_add_affine(pb, pa)
    assert point_add_affine(point_add_affine(pa, pb), pc) == point_add_affine(pa, point_add_affine(pb, pc))


@FAST
@given(scalars)
def test_inverse_and_identity(k: int) -> None:
    point = _mul(k)
    assert point_add_affine(point, point_negate_affine(point)) is None
    assert point_add_affine(point, None) == point


@FAST
@given(scalars, st.booleans())
def test_sec1_serialize_parse_round_trip(k: int, compressed: bool) -> None:
    point = _mul(k)
    assert point is not None
    encoded = serialize_sec1(point, compressed=compressed)
    assert parse_sec1(encoded) == point
    assert serialize_sec1(parse_sec1(encoded), compressed=compressed) == encoded


@FAST
@given(scalars)
def test_xonly_round_trip_recovers_even_y_representative(k: int) -> None:
    point = _mul(k)
    assert point is not None
    lifted = lift_x(int.from_bytes(serialize_xonly(point), "big"))
    assert has_even_y(lifted)
    assert lifted == (point if has_even_y(point) else point_negate_affine(point))


@FAST
@given(field_elements)
def test_sqrt_mod_p_returns_a_true_root_or_none(value: int) -> None:
    root = sqrt_mod_p(value)
    if root is None:
        assert pow(value, (P - 1) // 2, P) == P - 1  # Euler criterion: a non-residue
    else:
        assert root * root % P == value


@FAST
@given(field_elements)
def test_lift_x_succeeds_exactly_when_x_is_on_the_curve(x: int) -> None:
    on_curve = sqrt_mod_p(pow(x, 3, P) + 7) is not None
    try:
        point = lift_x(x)
    except ValueError:
        assert not on_curve
    else:
        assert on_curve and is_on_curve(point) and point[0] == x
