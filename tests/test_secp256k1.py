"""Known generator-multiple vectors for the reference secp256k1 implementation."""

import random

from keylab.advanced_suite import curve_add_geometry
from keylab.ec.secp256k1 import (
    _INFINITY,
    G,
    N,
    P,
    _to_affine,
    _to_jacobian,
    compress_pubkey,
    decompress_pubkey,
    ecdsa_sign_digest,
    ecdsa_verify_digest,
    glv_decompose,
    is_on_curve,
    point_add,
    point_add_affine,
    point_add_geometry,
    point_double,
    point_negate_affine,
    public_key_from_private_scalar,
    scalar_mult,
    wnaf_digits,
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


def test_public_key_is_exactly_private_scalar_times_generator() -> None:
    previous = None
    for private_scalar in (1, 2, 7, N - 1):
        public_key = public_key_from_private_scalar(private_scalar, backend="python")
        if private_scalar == 1:
            assert public_key == G
        if previous is not None and private_scalar == 2:
            assert public_key == point_add_affine(previous, G)
        assert is_on_curve(public_key)
        previous = public_key
    assert public_key_from_private_scalar(7, backend="python") == (
        0x5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC,
        0x6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA,
    )


def test_public_key_derivation_rejects_out_of_range_private_scalars() -> None:
    for private_scalar in (0, -1, N, N + 1, True):
        try:
            public_key_from_private_scalar(private_scalar)  # type: ignore[arg-type]
        except ValueError:
            pass
        else:
            raise AssertionError("invalid private scalar was accepted")


def test_rfc6979_ecdsa_sign_and_verify_digest() -> None:
    import hashlib

    digest = hashlib.sha256(b"Keylab signature precision vector").digest()
    private_scalar = 0x123456789ABCDEF
    public_key = public_key_from_private_scalar(private_scalar, backend="python")
    signature = ecdsa_sign_digest(digest, private_scalar, backend="python")
    assert signature == ecdsa_sign_digest(digest, private_scalar, backend="python")
    assert signature == (
        0x6C42FFBC4DCC91C105A8D0B41ADFA81A4B9DB75B37D3A3D31060C3EAE99301FB,
        0x25D7CBCC55D64FF2210D8DCCAF1E199BF54CE62ADD67B8678E0778DF8F10D2C0,
    )
    assert signature[0] in range(1, N)
    assert 1 <= signature[1] <= N // 2
    assert ecdsa_verify_digest(digest, signature, public_key)
    assert not ecdsa_verify_digest(hashlib.sha256(b"different").digest(), signature, public_key)
    assert not ecdsa_verify_digest(digest, (0, signature[1]), public_key)


def test_windowed_generator_multiplication_matches_double_and_add() -> None:
    rng = random.Random(0x256)
    scalars = [0, 1, 2, 15, 16, 17, N - 1, N, N + 1]
    scalars.extend(rng.randrange(1 << 256) for _ in range(30))

    for scalar in scalars:
        assert scalar_mult(scalar) == _double_and_add_reference(scalar)


def test_glv_split_and_joint_multiplication_match_reference() -> None:
    rng = random.Random(0x61A)
    scalars = [0, 1, 2, N - 1, N, N + 1]
    scalars.extend(rng.randrange(N) for _ in range(24))
    for scalar in scalars:
        k1, k2 = glv_decompose(scalar)
        assert (k1 + 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72 * k2 - scalar) % N == 0
        assert scalar_mult(scalar, backend="python-glv") == scalar_mult(scalar, backend="python")


def test_fixed_base_wnaf_matches_reference_and_reconstructs_scalar() -> None:
    rng = random.Random(0x574E4146)
    scalars = [0, 1, 2, 3, 15, 16, N - 1]
    scalars.extend(rng.randrange(N) for _ in range(12))
    for scalar in scalars:
        digits = wnaf_digits(scalar)
        assert sum(digit << bit for bit, digit in enumerate(digits)) == scalar
        assert all(digit == 0 or digit & 1 for digit in digits)
        assert scalar_mult(scalar, backend="python-wnaf") == scalar_mult(scalar, backend="python")


def test_full_affine_window_backend_matches_reference() -> None:
    rng = random.Random(0xAFF1AE)
    scalars = [0, 1, 2, 15, 16, N - 1, N, N + 1]
    scalars.extend(rng.randrange(N) for _ in range(12))
    for scalar in scalars:
        assert scalar_mult(scalar, backend="python-affine-window") == scalar_mult(scalar, backend="python")


def test_arbitrary_point_scalar_multiplication_still_uses_correct_group_result() -> None:
    point = scalar_mult(2)
    for scalar in (0, 1, 2, 3, 19):
        assert scalar_mult(scalar, point) == scalar_mult(2 * scalar)


def test_affine_curve_addition_uses_modular_inverse_and_matches_group_law() -> None:
    result = curve_add_geometry(G, G)
    assert result["sum"] == scalar_mult(2)
    assert result["slope"] is not None


def test_affine_point_operations_handle_identity_and_inverse() -> None:
    negative_generator = point_negate_affine(G)
    assert point_add_affine(G, None) == G
    assert point_add_affine(G, negative_generator) is None
    assert point_add_affine(G, G) == scalar_mult(2)


def test_point_add_geometry_reports_third_intersection_and_vertical_line() -> None:
    doubled = point_add_geometry(G, G)
    assert doubled["sum"] == scalar_mult(2)
    assert doubled["third_intersection"] == point_negate_affine(scalar_mult(2))
    vertical = point_add_geometry(G, point_negate_affine(G))
    assert vertical == {"slope": None, "third_intersection": None, "sum": None}


def test_affine_point_operations_reject_invalid_points() -> None:
    invalid = (1, 1)
    try:
        point_add_affine(invalid, G)
    except ValueError as exc:
        assert "not on secp256k1" in str(exc)
    else:
        raise AssertionError("invalid affine point was accepted")

from keylab.advanced_suite import (
    scalar_mult_g_fast,
    scalar_mult_naf,
)


def test_scalar_mult_naf_agrees() -> None:
    test_scalars = (
        1,
        2,
        3,
        7,
        31,
        255,
        65537,
        0xDEADBEEF,
        0xCAFEBABE,
    )

    for scalar in test_scalars:
        assert scalar_mult_g_fast(scalar) == scalar_mult_naf(scalar)
