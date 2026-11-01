"""Frozen textbook secp256k1 arithmetic: the oracle for validating optimizations.

Every optimized code path in KeyLab is checked against this module (see
docs/PERFORMANCE_VALIDATION.md). It is written for obviousness, not speed:
affine coordinates, one modular inversion per operation, left-to-right
double-and-add, and its own copy of the curve constants. It imports nothing from
the rest of KeyLab, so a bug in the optimized arithmetic cannot also hide here.

**Do not optimize this module.** A faster reference is a weaker reference. Change
it only to fix a demonstrated bug, with a test showing the bug.

Not constant-time; for validation and teaching only.
"""

from __future__ import annotations

# secp256k1 domain parameters (SEC 2, section 2.4.1), written out independently.
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
B = 7
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

Point = tuple[int, int] | None  # None is the point at infinity


def is_on_curve(point: Point) -> bool:
    """Return whether ``point`` is infinity or a field point with y^2 = x^3 + 7."""
    if point is None:
        return True
    x, y = point
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x - B) % P == 0


def negate(point: Point) -> Point:
    """Return -point: (x, -y), with -infinity = infinity."""
    if point is None:
        return None
    x, y = point
    return x, (-y) % P


def add(left: Point, right: Point) -> Point:
    """Add two affine points with the chord-and-tangent rule."""
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None  # P + (-P), including doubling a point with y = 0
        return double(left)
    slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def double(point: Point) -> Point:
    """Double an affine point with the tangent rule (a = 0 for secp256k1)."""
    if point is None:
        return None
    x, y = point
    if y == 0:
        return None
    slope = 3 * x * x * pow(2 * y, -1, P) % P
    x3 = (slope * slope - 2 * x) % P
    return x3, (slope * (x - x3) - y) % P


def scalar_mult(scalar: int, point: Point = G) -> Point:
    """Return scalar * point by left-to-right double-and-add.

    Follows the ``keylab.ec.secp256k1.scalar_mult`` contract: the scalar must be
    a non-negative int and is reduced modulo N (the group order of every finite
    point); the point must be on the curve; infinity is ``None``.
    """
    if type(scalar) is not int or scalar < 0:
        raise ValueError("scalar must be a non-negative int")
    if not is_on_curve(point):
        raise ValueError("point is not on secp256k1")
    result: Point = None
    for bit in bin(scalar % N)[2:]:
        result = double(result)
        if bit == "1":
            result = add(result, point)
    return result


def encode_compressed(point: Point) -> bytes:
    """SEC1 compressed encoding: 0x02/0x03 by y parity, then x (33 bytes)."""
    if point is None or not is_on_curve(point):
        raise ValueError("a finite curve point is required")
    x, y = point
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def encode_uncompressed(point: Point) -> bytes:
    """SEC1 uncompressed encoding: 0x04, x, y (65 bytes)."""
    if point is None or not is_on_curve(point):
        raise ValueError("a finite curve point is required")
    x, y = point
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def encode_xonly(point: Point) -> bytes:
    """BIP-340 x-only encoding: the 32-byte x coordinate."""
    if point is None or not is_on_curve(point):
        raise ValueError("a finite curve point is required")
    return point[0].to_bytes(32, "big")


def decode(data: bytes) -> tuple[int, int]:
    """Decode a SEC1 compressed or uncompressed public key, validating the point."""
    if len(data) == 65 and data[0] == 4:
        point = int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big")
    elif len(data) == 33 and data[0] in (2, 3):
        x = int.from_bytes(data[1:], "big")
        if x >= P:
            raise ValueError("x coordinate is not a field element")
        y = pow((x * x * x + B) % P, (P + 1) // 4, P)  # square root, since P % 4 == 3
        if (y * y - x * x * x - B) % P != 0:
            raise ValueError("x coordinate is not on the curve")
        if y & 1 != data[0] & 1:
            y = P - y
        point = x, y
    else:
        raise ValueError("not a SEC1 compressed or uncompressed public key")
    if not is_on_curve(point):
        raise ValueError("point is not on secp256k1")
    return point


__all__ = [
    "B",
    "G",
    "N",
    "P",
    "add",
    "decode",
    "double",
    "encode_compressed",
    "encode_uncompressed",
    "encode_xonly",
    "is_on_curve",
    "negate",
    "scalar_mult",
]
