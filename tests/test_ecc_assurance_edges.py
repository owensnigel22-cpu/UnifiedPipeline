import pytest
from ecdsa import SECP256k1

from keylab.ec.secp256k1 import G, N, scalar_mult


def test_scalar_mult_zero_valid_point_and_infinity_still_return_infinity() -> None:
    assert scalar_mult(0, G) is None
    assert scalar_mult(0, None) is None
    assert scalar_mult(1, None) is None


def test_scalar_mult_rejects_invalid_point_even_for_zero_scalar() -> None:
    with pytest.raises(ValueError, match="point is not on secp256k1"):
        scalar_mult(0, (1, 1))


def test_scalar_mult_rejects_negative_scalar() -> None:
    with pytest.raises(ValueError):
        scalar_mult(-1, G)


def test_scalar_mult_normalizes_large_scalar_against_independent_ecdsa_reference() -> None:
    scalar = (1 << 300) + 0x123456789ABCDEF
    reference_point = SECP256k1.generator * (scalar % N)

    assert scalar_mult(scalar, G) == (int(reference_point.x()), int(reference_point.y()))
