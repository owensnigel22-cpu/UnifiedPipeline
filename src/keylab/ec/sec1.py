"""SEC1 public-key serialization helpers for secp256k1."""

from __future__ import annotations

from keylab.ec.secp256k1 import P, Point, compress_pubkey, decompress_pubkey, is_on_curve


def parse_sec1(data: bytes) -> tuple[int, int]:
    """Parse a compressed or uncompressed SEC1 public key and validate the point."""
    if not isinstance(data, bytes):
        raise TypeError("SEC1 public key must be bytes")
    if len(data) == 33 and data[0] in (2, 3):
        return decompress_pubkey(data)
    if len(data) == 65 and data[0] == 4:
        point = (int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big"))
        if not is_on_curve(point):
            raise ValueError("uncompressed SEC1 public key is not on secp256k1")
        return point
    raise ValueError("SEC1 public key must be 33-byte compressed or 65-byte uncompressed encoding")


def serialize_sec1(point: Point, *, compressed: bool = True) -> bytes:
    """Serialize a finite secp256k1 point in compressed or uncompressed SEC1 form."""
    if point is None or not is_on_curve(point):
        raise ValueError("a finite secp256k1 point is required")
    if compressed:
        return compress_pubkey(point)
    x, y = point
    if not (0 <= x < P and 0 <= y < P):
        raise ValueError("point coordinates are outside the field")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def serialize_uncompressed(point: Point) -> bytes:
    """Serialize a finite point using the 65-byte SEC1 uncompressed form."""
    return serialize_sec1(point, compressed=False)


def serialize_xonly(point: Point) -> bytes:
    """Return the 32-byte x coordinate used by BIP-340/BIP-341.

    X-only encodings omit y parity. Protocols that parse them lift x to the
    even-y point; callers needing a complete SEC1 point should use
    :func:`serialize_sec1` instead.
    """
    if point is None or not is_on_curve(point):
        raise ValueError("a finite secp256k1 point is required")
    x, _ = point
    if not 0 <= x < P:
        raise ValueError("point coordinates are outside the field")
    return x.to_bytes(32, "big")


__all__ = ["parse_sec1", "serialize_sec1", "serialize_uncompressed", "serialize_xonly"]
