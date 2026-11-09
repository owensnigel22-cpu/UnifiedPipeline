"""Explicit optional Coincurve adapters for secp256k1 ECDSA operations.

The pure-Python operations remain the reference implementation. These
wrappers use libsecp256k1 through Coincurve and never silently fall back.
"""

from __future__ import annotations

from keylab.ec.sec1 import serialize_sec1
from keylab.ec.secp256k1 import N, Point, ecdsa_sign_digest, is_on_curve


def _coincurve():
    try:
        from coincurve import PrivateKey, PublicKey
    except (ImportError, OSError) as exc:
        raise ImportError(
            "install KeyLab's optional Coincurve backend with `pip install 'keylab[fast]'`"
        ) from exc
    return PrivateKey, PublicKey


def _der_integer(value: int) -> bytes:
    encoded = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + bytes((len(encoded),)) + encoded


def _encode_signature_der(signature: tuple[int, int]) -> bytes:
    r, s = signature
    body = _der_integer(r) + _der_integer(s)
    return b"\x30" + bytes((len(body),)) + body


def _decode_signature_der(encoded: bytes) -> tuple[int, int]:
    if len(encoded) < 8 or len(encoded) > 72 or encoded[0] != 0x30:
        raise ValueError("Coincurve returned malformed DER signature")
    if encoded[1] != len(encoded) - 2 or encoded[2] != 0x02:
        raise ValueError("Coincurve returned malformed DER signature")
    r_len = encoded[3]
    r_start, r_end = 4, 4 + r_len
    if r_len == 0 or r_end + 2 > len(encoded) or encoded[r_end] != 0x02:
        raise ValueError("Coincurve returned malformed DER signature")
    s_len = encoded[r_end + 1]
    s_start, s_end = r_end + 2, r_end + 2 + s_len
    if s_len == 0 or s_end != len(encoded):
        raise ValueError("Coincurve returned malformed DER signature")
    values = (encoded[r_start:r_end], encoded[s_start:s_end])
    for value in values:
        if value[0] & 0x80 or (len(value) > 1 and value[0] == 0 and not value[1] & 0x80):
            raise ValueError("Coincurve returned non-canonical DER signature")
    return tuple(int.from_bytes(value, "big") for value in values)  # type: ignore[return-value]


def ecdsa_sign_digest_coincurve(digest: bytes, private_scalar: int) -> tuple[int, int]:
    """Sign a 32-byte digest with libsecp256k1 and return raw low-S ``(r, s)``.

    Unlike the Python reference, signing secret values is delegated to native
    libsecp256k1. This does not certify the caller's broader process as
    constant-time or audited.
    """
    if type(digest) is not bytes or len(digest) != 32:
        raise ValueError("digest must be exactly 32 bytes")
    if type(private_scalar) is not int or not 1 <= private_scalar < N:
        raise ValueError("private scalar must be an integer in [1, N-1]")
    PrivateKey, _ = _coincurve()
    der = PrivateKey(private_scalar.to_bytes(32, "big")).sign(digest, hasher=None)
    return _decode_signature_der(der)


def ecdsa_verify_digest_coincurve(
    digest: bytes, signature: tuple[int, int], public_key: Point
) -> bool:
    """Verify a raw ECDSA signature with libsecp256k1; malformed input is false.

    High-S signatures are accepted by normalizing ``s`` to its equivalent
    low-S representative, matching KeyLab's mathematical verifier.
    """
    if not isinstance(digest, (bytes, bytearray, memoryview)) or len(digest) != 32:
        return False
    if not isinstance(signature, (tuple, list)) or len(signature) != 2:
        return False
    if any(type(value) is not int for value in signature):
        return False
    if not isinstance(public_key, (tuple, list)) or len(public_key) != 2:
        return False
    if any(type(value) is not int for value in public_key):
        return False
    point = (public_key[0], public_key[1])
    r, s = signature
    if not (is_on_curve(point) and 1 <= r < N and 1 <= s < N):
        return False
    s = min(s, N - s)
    _, PublicKey = _coincurve()
    try:
        return PublicKey(serialize_sec1(point, compressed=True)).verify(
            _encode_signature_der((r, s)), bytes(digest), hasher=None
        )
    except (ValueError, TypeError):
        return False


def ecdsa_sign_digest_python(digest: bytes, private_scalar: int) -> tuple[int, int]:
    """Named pure-Python reference helper for backend differential tests."""
    return ecdsa_sign_digest(digest, private_scalar, backend="python")


__all__ = [
    "ecdsa_sign_digest_coincurve",
    "ecdsa_sign_digest_python",
    "ecdsa_verify_digest_coincurve",
]
