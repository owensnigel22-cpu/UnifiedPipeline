"""Known generator-multiple vectors for the reference secp256k1 implementation."""

import random

from keylab.ec.secp256k1 import (
    _INFINITY,
    G,
    N,
    P,
    _to_affine,
    _to_jacobian,
    compress_pubkey,
    decompress_pubkey,
    is_on_curve,
    point_add,
    point_double,
    scalar_mult,
)


def _double_and_add_reference(scalar: int) -> tuple[int, int] | None:
    result = _INFINITY
    addend = _to_jacobian(G)
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        scalar >>= 1
    return _to_affine(result)


def test_generator_and_double_generator_vectors() -> None:
    assert scalar_mult(1) == G
    x, y = G
    slope = 3 * x * x * pow(2 * y, P - 2, P) % P
    expected_double = ((slope * slope - 2 * x) % P, (slope * (x - ((slope * slope - 2 * x) % P)) - y) % P)
    assert scalar_mult(2) == expected_double


def test_compressed_public_key_round_trip() -> None:
    for scalar in (1, 2, 7):
        point = scalar_mult(scalar)
        assert is_on_curve(point)
        assert decompress_pubkey(compress_pubkey(point)) == point


def test_windowed_generator_multiplication_matches_double_and_add() -> None:
    rng = random.Random(0x256)
    scalars = [0, 1, 2, 15, 16, 17, N - 1, N, N + 1]
    scalars.extend(rng.randrange(1 << 256) for _ in range(30))

    for scalar in scalars:
        assert scalar_mult(scalar) == _double_and_add_reference(scalar)


def test_arbitrary_point_scalar_multiplication_still_uses_correct_group_result() -> None:
    point = scalar_mult(2)
    for scalar in (0, 1, 2, 3, 19):
        assert scalar_mult(scalar, point) == scalar_mult(2 * scalar)