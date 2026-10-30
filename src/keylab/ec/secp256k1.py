"""Reference secp256k1 point arithmetic; not constant-time and not a full-key-search facility."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterator
from functools import lru_cache
from importlib.util import find_spec

from keylab.numtheory.core import mod_inverse_builtin

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G: tuple[int, int] = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
Point = tuple[int, int] | None
Jacobian = tuple[int, int, int]
_INFINITY: Jacobian = (0, 1, 0)
_GENERATOR_WINDOW_BITS = 4
_AFFINE_WINDOW_BITS = 4
_AFFINE_WINDOW_COUNT = (256 + _AFFINE_WINDOW_BITS - 1) // _AFFINE_WINDOW_BITS
_WNAF_WINDOW_BITS = 5
BETA = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE
LAMBDA = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
_GLV_MINUS_B1 = 0xE4437ED6010E88286F547FA90ABFE4C3
_GLV_MINUS_B2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE8A280AC50774346DD765CDA83DB1562C
_GLV_G1 = 0x3086D221A7D46BCDE86C90E49284EB153DAA8A1471E8CA7FE893209A45DBB031
_GLV_G2 = 0xE4437ED6010E88286F547FA90ABFE4C4221208AC9DF506C61571B4AE8AC47F71


def is_on_curve(point: Point) -> bool:
    """Return whether an affine point is infinity or satisfies secp256k1's curve equation."""
    return point is None or (
        0 <= point[0] < P and 0 <= point[1] < P and (point[1] * point[1] - point[0] ** 3 - 7) % P == 0
    )


def sqrt_mod_p(value: int) -> int | None:
    """Return a square root of ``value`` modulo P, or ``None`` for a non-residue.

    secp256k1's field prime satisfies ``P % 4 == 3``, so a candidate root is
    ``value^((P+1)/4)``. The candidate is checked because non-residues also
    produce a value. This is the single shared square-root routine used by
    point decompression, x-only lifting, and signature public-key recovery.
    """
    value %= P
    root = pow(value, (P + 1) // 4, P)
    return root if root * root % P == value else None


def y_from_x(x: int, *, odd: bool = False) -> int:
    """Return the curve y coordinate for ``x`` with the requested parity."""
    if type(x) is not int or not 0 <= x < P:
        raise ValueError("x coordinate must be in the secp256k1 field")
    y = sqrt_mod_p(pow(x, 3, P) + 7)
    if y is None:
        raise ValueError("x coordinate does not lift to secp256k1")
    return y if bool(y & 1) == odd else P - y


def lift_x(x: int) -> tuple[int, int]:
    """Lift an x coordinate to the even-y point, as BIP-340 and BIP-341 require."""
    return x, y_from_x(x, odd=False)


def has_even_y(point: Point) -> bool:
    """Return whether a finite point has an even y coordinate."""
    if point is None:
        raise ValueError("the point at infinity has no y coordinate")
    return point[1] % 2 == 0


def require_point(point: Point, *, name: str = "point") -> tuple[int, int]:
    """Validate a finite secp256k1 affine point and return it narrowed for typing."""
    if point is None:
        raise ValueError(f"{name} must not be the point at infinity")
    if not isinstance(point, tuple) or len(point) != 2 or not is_on_curve(point):
        raise ValueError(f"{name} is not a valid secp256k1 point")
    return point


def require_scalar(scalar: int, *, name: str = "scalar") -> int:
    """Validate an integer scalar in ``[1, N-1]``."""
    if type(scalar) is not int or not 1 <= scalar < N:
        raise ValueError(f"{name} must be an integer in [1, N-1]")
    return scalar


def point_negate_affine(point: Point) -> Point:
    """Negate an affine secp256k1 point; infinity is represented by ``None``."""
    if point is None:
        return None
    if not is_on_curve(point):
        raise ValueError("point is not on secp256k1")
    return point[0], (-point[1]) % P


def point_add_affine(left: Point, right: Point) -> Point:
    """Add affine secp256k1 points, returning ``None`` for the point at infinity.

    This readable affine implementation is intended for geometry and learning.
    Repeated operations should use the Jacobian-backed :func:`scalar_mult` API.
    """
    for point in (left, right):
        if point is not None and not is_on_curve(point):
            raise ValueError("point is not on secp256k1")
    if left is None:
        return right
    if right is None:
        return left

    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1 * mod_inverse_builtin(2 * y1, P)) % P
    else:
        slope = ((y2 - y1) * mod_inverse_builtin(x2 - x1, P)) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def point_add_geometry(left: Point, right: Point) -> dict[str, object]:
    """Explain affine secant/tangent addition, including its third intersection.

    The third intersection is the reflection of the group sum across the
    x-axis. For a vertical line it is the point at infinity (``None``).
    """
    total = point_add_affine(left, right)
    if left is None or right is None:
        return {"slope": None, "third_intersection": None, "sum": total}
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return {"slope": None, "third_intersection": None, "sum": None}
    if left == right:
        slope = (3 * x1 * x1 * mod_inverse_builtin(2 * y1, P)) % P
    else:
        slope = ((y2 - y1) * mod_inverse_builtin(x2 - x1, P)) % P
    assert total is not None
    third_intersection = point_negate_affine(total)
    return {"slope": slope, "third_intersection": third_intersection, "sum": total}


def _to_jacobian(point: Point) -> Jacobian:
    return _INFINITY if point is None else (point[0], point[1], 1)


def _to_affine(point: Jacobian) -> Point:
    x, y, z = point
    if z % P == 0:
        return None
    inverse = mod_inverse_builtin(z, P)
    inverse2 = inverse * inverse % P
    return x * inverse2 % P, y * inverse2 * inverse % P


def point_double(point: Jacobian) -> Jacobian:
    """Double a Jacobian secp256k1 point."""
    x, y, z = point
    if z % P == 0 or y % P == 0:
        return _INFINITY
    yy = y * y % P
    yyyy = yy * yy % P
    s = 4 * x * yy % P
    m = 3 * x * x % P
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * yyyy) % P
    z3 = 2 * y * z % P
    return x3, y3, z3


def point_add(left: Jacobian, right: Jacobian) -> Jacobian:
    """Add two Jacobian secp256k1 points."""
    x1, y1, z1 = left
    x2, y2, z2 = right
    if z1 % P == 0:
        return x2 % P, y2 % P, z2 % P
    if z2 % P == 0:
        return x1 % P, y1 % P, z1 % P
    z1z1, z2z2 = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2z2 % P, x2 * z1z1 % P
    s1 = y1 * z2 * z2z2 % P
    s2 = y2 * z1 * z1z1 % P
    if u1 == u2:
        return point_double(left) if s1 == s2 else _INFINITY
    h = (u2 - u1) % P
    r = (s2 - s1) % P
    h2, h3 = h * h % P, h * h * h % P
    x3 = (r * r - h3 - 2 * u1 * h2) % P
    y3 = (r * (u1 * h2 - x3) - s1 * h3) % P
    z3 = h * z1 * z2 % P
    return x3, y3, z3


def _point_add_mixed(left: Jacobian, right: Point) -> Jacobian:
    """Add a Jacobian point and an affine point without normalizing either result."""
    if right is None:
        return left
    if left[2] % P == 0:
        return _to_jacobian(right)
    x1, y1, z1 = left
    x2, y2 = right
    z1_squared = z1 * z1 % P
    u2 = x2 * z1_squared % P
    s2 = y2 * z1 * z1_squared % P
    if x1 % P == u2:
        return point_double(left) if y1 % P == s2 else _INFINITY
    h = (u2 - x1) % P
    r = (s2 - y1) % P
    h_squared = h * h % P
    h_cubed = h * h_squared % P
    x3 = (r * r - h_cubed - 2 * x1 * h_squared) % P
    y3 = (r * (x1 * h_squared - x3) - y1 * h_cubed) % P
    z3 = h * z1 % P
    return x3, y3, z3


@lru_cache(maxsize=1)
def _generator_window_table() -> tuple[Jacobian, ...]:
    """Return cached Jacobian multiples 0*G through 15*G for fixed-base multiplication."""
    multiples = [_INFINITY, _to_jacobian(G)]
    for _ in range(2, 1 << _GENERATOR_WINDOW_BITS):
        multiples.append(point_add(multiples[-1], _to_jacobian(G)))
    return tuple(multiples)


def _scalar_mult_generator(scalar: int) -> Point:
    """Multiply the fixed generator using a cached four-bit positional window."""
    table = _generator_window_table()
    result = _INFINITY
    window_count = (scalar.bit_length() + _GENERATOR_WINDOW_BITS - 1) // _GENERATOR_WINDOW_BITS
    for window_index in range(window_count - 1, -1, -1):
        for _ in range(_GENERATOR_WINDOW_BITS):
            result = point_double(result)
        digit = (scalar >> (window_index * _GENERATOR_WINDOW_BITS)) & (
            (1 << _GENERATOR_WINDOW_BITS) - 1
        )
        if digit:
            result = point_add(result, table[digit])
    return _to_affine(result)


@lru_cache(maxsize=1)
def _generator_affine_window_table() -> tuple[tuple[Point, ...], ...]:
    """Precompute 4-bit multiples for every generator window, batch-normalized."""
    jacobian_windows: list[tuple[Jacobian, ...]] = []
    base = _to_jacobian(G)
    for _ in range(_AFFINE_WINDOW_COUNT):
        multiples = [_INFINITY]
        current = base
        for _digit in range(1, 1 << _AFFINE_WINDOW_BITS):
            multiples.append(current)
            current = point_add(current, base)
        jacobian_windows.append(tuple(multiples))
        for _ in range(_AFFINE_WINDOW_BITS):
            base = point_double(base)

    z_values = [point[2] % P for window in jacobian_windows for point in window[1:]]
    prefixes: list[int] = []
    product = 1
    for z_value in z_values:
        if z_value == 0:
            raise ArithmeticError("fixed-base table contains a point at infinity")
        prefixes.append(product)
        product = product * z_value % P
    inverse_product = mod_inverse_builtin(product, P)
    z_inverses = [0] * len(z_values)
    for index in range(len(z_values) - 1, -1, -1):
        z_value = z_values[index]
        z_inverses[index] = inverse_product * prefixes[index] % P
        inverse_product = inverse_product * z_value % P

    affine_windows: list[tuple[Point, ...]] = []
    inverse_index = 0
    for window in jacobian_windows:
        affine: list[Point] = [None]
        for x, y, _z in window[1:]:
            z_inverse = z_inverses[inverse_index]
            inverse_index += 1
            inverse_squared = z_inverse * z_inverse % P
            affine.append((x * inverse_squared % P, y * inverse_squared * z_inverse % P))
        affine_windows.append(tuple(affine))
    return tuple(affine_windows)


def _scalar_mult_generator_affine_window(scalar: int) -> Point:
    """Multiply G with a full 64-window table and Jacobian/affine mixed adds."""
    table = _generator_affine_window_table()
    result = _INFINITY
    digit_mask = (1 << _AFFINE_WINDOW_BITS) - 1
    for window_index, multiples in enumerate(table):
        digit = (scalar >> (window_index * _AFFINE_WINDOW_BITS)) & digit_mask
        if digit:
            point = multiples[digit]
            assert point is not None
            result = _point_add_mixed(result, point)
    return _to_affine(result)


def wnaf_digits(scalar: int, window: int = _WNAF_WINDOW_BITS) -> tuple[int, ...]:
    """Return least-significant-first width-w NAF digits for a nonnegative scalar."""
    if type(scalar) is not int or scalar < 0:
        raise ValueError("scalar must be a nonnegative integer")
    if type(window) is not int or not 2 <= window <= 8:
        raise ValueError("window must be between 2 and 8")
    digits: list[int] = []
    radix = 1 << window
    midpoint = radix >> 1
    while scalar:
        if scalar & 1:
            digit = scalar % radix
            if digit >= midpoint:
                digit -= radix
            scalar -= digit
            digits.append(digit)
        else:
            digits.append(0)
        scalar >>= 1
    return tuple(digits)


@lru_cache(maxsize=1)
def _generator_wnaf_table() -> tuple[Jacobian, ...]:
    """Precompute odd multiples G, 3G, ... for fixed-base width-w NAF."""
    count = 1 << (_WNAF_WINDOW_BITS - 2)
    generator = _to_jacobian(G)
    twice = point_double(generator)
    table = [generator]
    for _ in range(1, count):
        table.append(point_add(table[-1], twice))
    return tuple(table)


def _scalar_mult_generator_wnaf(scalar: int) -> Point:
    digits = wnaf_digits(scalar)
    table = _generator_wnaf_table()
    result = _INFINITY
    for digit in reversed(digits):
        result = point_double(result)
        if digit:
            multiple = table[(abs(digit) - 1) // 2]
            if digit < 0:
                x, y, z = multiple
                multiple = x, (-y) % P, z
            result = point_add(result, multiple)
    return _to_affine(result)


def _scalar_mult_python(scalar: int, point: Point) -> Point:
    """Compute scalar times an affine point using the readable Python implementation."""
    if point is None or scalar == 0:
        return None
    if not is_on_curve(point):
        raise ValueError("point is not on secp256k1")
    if point == G:
        return _scalar_mult_generator(scalar)
    result = _INFINITY
    addend = _to_jacobian(point)
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        scalar >>= 1
    return _to_affine(result)


def glv_decompose(scalar: int) -> tuple[int, int]:
    """Split k into signed components satisfying k = k1 + lambda*k2 (mod N)."""
    if type(scalar) is not int:
        raise TypeError("scalar must be an integer")
    scalar %= N
    c1 = (scalar * _GLV_G1 + (1 << 383)) >> 384
    c2 = (scalar * _GLV_G2 + (1 << 383)) >> 384
    k2 = (c1 * _GLV_MINUS_B1 + c2 * _GLV_MINUS_B2) % N
    k1 = (scalar - LAMBDA * k2) % N
    if k1 > N // 2:
        k1 -= N
    if k2 > N // 2:
        k2 -= N
    if (k1 + LAMBDA * k2 - scalar) % N:
        raise ArithmeticError("GLV scalar decomposition identity failed")
    return k1, k2


def _scalar_mult_glv(scalar: int, point: Point) -> Point:
    """Experimental joint multiplication using secp256k1's GLV endomorphism."""
    if point is None or scalar == 0:
        return None
    k1, k2 = glv_decompose(scalar)
    phi = (BETA * point[0] % P, point[1])
    point1 = point_negate_affine(point) if k1 < 0 else point
    point2 = point_negate_affine(phi) if k2 < 0 else phi
    k1, k2 = abs(k1), abs(k2)
    add1, add2 = _to_jacobian(point1), _to_jacobian(point2)
    result = _INFINITY
    for bit in range(max(k1.bit_length(), k2.bit_length()) - 1, -1, -1):
        result = point_double(result)
        if (k1 >> bit) & 1:
            result = point_add(result, add1)
        if (k2 >> bit) & 1:
            result = point_add(result, add2)
    return _to_affine(result)


def _scalar_mult_coincurve(scalar: int, point: Point) -> Point:
    """Use libsecp256k1 through coincurve for fast secp256k1 multiplication."""
    from coincurve import PrivateKey, PublicKey

    scalar_bytes = scalar.to_bytes(32, "big")
    if point == G:
        public_key = PrivateKey(scalar_bytes).public_key
    else:
        assert point is not None
        public_key = PublicKey.from_point(*point).multiply(scalar_bytes)
    encoded = public_key.format(compressed=False)
    return int.from_bytes(encoded[1:33], "big"), int.from_bytes(encoded[33:65], "big")


@lru_cache(maxsize=1)
def _fastecdsa_curve():
    from fastecdsa.curve import Curve

    return Curve("secp256k1", P, 0, 7, N, G[0], G[1])


def _scalar_mult_fastecdsa(scalar: int, point: Point) -> Point:
    from fastecdsa.point import Point as FastPoint

    assert point is not None
    result = scalar * FastPoint(point[0], point[1], _fastecdsa_curve())
    return int(result.x), int(result.y)


def scalar_mult(
    scalar: int,
    point: Point = G,
    *,
    backend: str = "auto",
) -> Point:
    """Multiply a point, preferring installed native backends and retaining Python fallback.

    ``backend`` may be ``auto``, ``python``, ``python-affine-window``,
    ``python-glv``, ``python-wnaf``, ``coincurve``, or ``fastecdsa``.
    The Python implementation is retained as the reference path. For secret-key
    operations, prefer a reviewed native library such as libsecp256k1.
    """
    if scalar < 0:
        raise ValueError("scalar must be non-negative")
    if backend not in {
        "auto", "python", "python-affine-window", "python-glv", "python-wnaf", "coincurve", "fastecdsa"
    }:
        raise ValueError(
            "backend must be auto, python, python-affine-window, python-glv, python-wnaf, coincurve, or fastecdsa"
        )
    if point is None or scalar == 0:
        return None
    if not is_on_curve(point):
        raise ValueError("point is not on secp256k1")
    scalar %= N
    if scalar == 0:
        return None

    if backend == "auto":
        for name, operation in (
            ("coincurve", _scalar_mult_coincurve),
            ("fastecdsa", _scalar_mult_fastecdsa),
        ):
            if find_spec(name) is not None:
                try:
                    return operation(scalar, point)
                except (ImportError, OSError):
                    continue
        if point == G:
            return _scalar_mult_generator_affine_window(scalar)
        return _scalar_mult_python(scalar, point)
    if backend == "coincurve":
        try:
            return _scalar_mult_coincurve(scalar, point)
        except ImportError as exc:
            raise ImportError(
                "install Keylab's coincurve extra: pip install 'keylab[secp256k1]'"
            ) from exc
    if backend == "fastecdsa":
        try:
            return _scalar_mult_fastecdsa(scalar, point)
        except ImportError as exc:
            raise ImportError("install Keylab's fastecdsa extra: pip install 'keylab[ecc-alt]'") from exc
    if backend == "python-wnaf":
        if point == G:
            return _scalar_mult_generator_wnaf(scalar)
        return _scalar_mult_python(scalar, point)
    if backend == "python-affine-window":
        if point == G:
            return _scalar_mult_generator_affine_window(scalar)
        return _scalar_mult_python(scalar, point)
    if backend == "python-glv":
        return _scalar_mult_glv(scalar, point)
    return _scalar_mult_python(scalar, point)


def public_key_from_private_scalar(private_scalar: int, *, backend: str = "auto") -> tuple[int, int]:
    """Derive secp256k1 public key ``Q = d*G`` for a valid private scalar ``d``."""
    if type(private_scalar) is not int or not 1 <= private_scalar < N:
        raise ValueError("private scalar must be an integer in [1, N-1]")
    point = scalar_mult(private_scalar, G, backend=backend)
    if point is None or not is_on_curve(point):
        raise ArithmeticError("public-key multiplication returned an invalid point")
    return point


def _rfc6979_candidates(private_scalar: int, digest: bytes) -> Iterator[int]:
    """Yield successive valid RFC 6979 candidates, including rare signing retries."""
    octets = private_scalar.to_bytes(32, "big")
    reduced_digest = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    value = b"\x01" * 32
    key = b"\x00" * 32
    key = hmac.new(key, value + b"\x00" + octets + reduced_digest, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(key, value + b"\x01" + octets + reduced_digest, hashlib.sha256).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        candidate = int.from_bytes(value, "big")
        if 1 <= candidate < N:
            yield candidate
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()


def rfc6979_nonce_from_digest(private_scalar: int, digest: bytes) -> int:
    """Return the RFC 6979 HMAC-SHA-256 nonce for a 32-byte digest and valid key."""
    if type(private_scalar) is not int or not 1 <= private_scalar < N:
        raise ValueError("private scalar must be an integer in [1, N-1]")
    if type(digest) is not bytes or len(digest) != 32:
        raise ValueError("digest must be exactly 32 bytes")
    return next(_rfc6979_candidates(private_scalar, digest))


def ecdsa_sign_digest(
    digest: bytes, private_scalar: int, *, backend: str = "auto"
) -> tuple[int, int]:
    """Create a deterministic, low-S ECDSA signature over one 32-byte digest.

    This readable Python signer is for learning and validation. Use a reviewed
    constant-time native implementation for production secret-key signing.
    """
    if type(digest) is not bytes or len(digest) != 32:
        raise ValueError("digest must be exactly 32 bytes")
    if type(private_scalar) is not int or not 1 <= private_scalar < N:
        raise ValueError("private scalar must be an integer in [1, N-1]")
    z = int.from_bytes(digest, "big")
    for nonce in _rfc6979_candidates(private_scalar, digest):
        nonce_point = scalar_mult(nonce, G, backend=backend)
        if nonce_point is None:
            continue
        r = nonce_point[0] % N
        if not r:
            continue
        s = (pow(nonce, -1, N) * (z + r * private_scalar)) % N
        if s:
            return r, min(s, N - s)
    raise ArithmeticError("RFC 6979 failed to produce a valid ECDSA signature")


def ecdsa_verify_digest(digest: bytes, signature: tuple[int, int], public_key: Point) -> bool:
    """Verify a raw ``(r, s)`` ECDSA signature over a 32-byte digest."""
    if len(digest) != 32 or public_key is None or not is_on_curve(public_key):
        return False
    if len(signature) != 2:
        return False
    r, s = signature
    if type(r) is not int or type(s) is not int or not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(digest, "big")
    inverse_s = pow(s, -1, N)
    left = scalar_mult((z * inverse_s) % N, G)
    right = scalar_mult((r * inverse_s) % N, public_key)
    total = point_add_affine(left, right)
    return total is not None and total[0] % N == r


def is_high_s_signature(signature: tuple[int, int]) -> bool:
    """Return whether a valid-range ECDSA signature uses the non-low-S form."""
    if len(signature) != 2:
        raise ValueError("signature must contain exactly r and s")
    r, s = signature
    if type(r) is not int or type(s) is not int or not (1 <= r < N and 1 <= s < N):
        raise ValueError("ECDSA signature values must be in [1, N-1]")
    return s > N // 2


def recover_private_key_from_reused_nonce(
    digest1: bytes,
    signature1: tuple[int, int],
    digest2: bytes,
    signature2: tuple[int, int],
    public_key: Point,
) -> int | None:
    """Recover an ECDSA private scalar from two signatures sharing one nonce.

    Returns ``None`` unless the signatures have the same ``r`` and a candidate
    scalar both matches ``public_key`` and verifies both signatures. The
    second nonce sign is tried both ways to handle ECDSA's ``k``/``-k`` point
    ambiguity and low-S normalization. Educational recovery helper only.
    """
    if (type(digest1) is not bytes or len(digest1) != 32
            or type(digest2) is not bytes or len(digest2) != 32):
        raise ValueError("digests must each be exactly 32 bytes")
    if public_key is None or not is_on_curve(public_key):
        return None
    if len(signature1) != 2 or len(signature2) != 2:
        return None
    r1, s1 = signature1
    r2, s2 = signature2
    if any(type(value) is not int or not 1 <= value < N for value in (r1, s1, r2, s2)):
        return None
    if r1 != r2:
        return None
    z1, z2 = int.from_bytes(digest1, "big"), int.from_bytes(digest2, "big")
    for nonce_sign in (1, -1):
        denominator = (s1 - nonce_sign * s2) % N
        if denominator == 0:
            continue
        nonce = ((z1 - z2) * pow(denominator, -1, N)) % N
        if nonce == 0:
            continue
        private_scalar = ((s1 * nonce - z1) * pow(r1, -1, N)) % N
        if not 1 <= private_scalar < N:
            continue
        if scalar_mult(private_scalar, G) != public_key:
            continue
        if (ecdsa_verify_digest(digest1, signature1, public_key)
                and ecdsa_verify_digest(digest2, signature2, public_key)):
            return private_scalar
    return None


def compress_pubkey(point: Point) -> bytes:
    """Serialize a finite affine point using SEC compressed format."""
    if point is None or not is_on_curve(point):
        raise ValueError("a finite secp256k1 point is required")
    x, y = point
    return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")


def decompress_pubkey(data: bytes) -> tuple[int, int]:
    """Parse a 33-byte compressed SEC public key and validate the resulting curve point."""
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError("compressed public key must be 33 bytes and start with 0x02 or 0x03")
    x = int.from_bytes(data[1:], "big")
    if x >= P:
        raise ValueError("public-key x coordinate is outside the field")
    try:
        return x, y_from_x(x, odd=bool(data[0] & 1))
    except ValueError as exc:
        raise ValueError("compressed public key is not on secp256k1") from exc
