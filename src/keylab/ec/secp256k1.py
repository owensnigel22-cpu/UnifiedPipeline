"""Reference secp256k1 point arithmetic; not constant-time and not a full-key-search facility."""

from __future__ import annotations

from functools import lru_cache
from importlib.util import find_spec

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


def is_on_curve(point: Point) -> bool:
    """Return whether an affine point is infinity or satisfies secp256k1's curve equation."""
    return point is None or (
        0 <= point[0] < P and 0 <= point[1] < P and (point[1] * point[1] - point[0] ** 3 - 7) % P == 0
    )


def _to_jacobian(point: Point) -> Jacobian:
    return _INFINITY if point is None else (point[0], point[1], 1)


def _to_affine(point: Jacobian) -> Point:
    x, y, z = point
    if z % P == 0:
        return None
    inverse = pow(z, P - 2, P)
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

    ``backend`` may be ``auto``, ``python``, ``coincurve``, or ``fastecdsa``.
    The Python implementation is retained as the reference path. For secret-key
    operations, prefer a reviewed native library such as libsecp256k1.
    """
    if scalar < 0:
        raise ValueError("scalar must be non-negative")
    if backend not in {"auto", "python", "coincurve", "fastecdsa"}:
        raise ValueError("backend must be auto, python, coincurve, or fastecdsa")
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
    return _scalar_mult_python(scalar, point)


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
    y_squared = (pow(x, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)
    if y * y % P != y_squared:
        raise ValueError("compressed public key is not on secp256k1")
    if y & 1 != data[0] & 1:
        y = P - y
    return x, y
