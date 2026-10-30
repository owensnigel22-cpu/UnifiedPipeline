"""BIP-340 Schnorr signing and verification primitives for secp256k1.

Messages may have any length, matching the 2022 revision of BIP-340 (official
test vectors 15-18). Bitcoin's Taproot signatures always sign a 32-byte
sighash, which is simply one particular message length.
"""

from __future__ import annotations

import secrets

from keylab.ec.secp256k1 import (
    G,
    N,
    P,
    lift_x,
    point_add_affine,
    point_negate_affine,
    scalar_mult,
)
from keylab.hashes.tagged import tagged_hash


def _lift_x_even(x: int) -> tuple[int, int] | None:
    """Return the even-y point for ``x``, or ``None`` when x is not a valid coordinate."""
    try:
        return lift_x(x)
    except ValueError:
        return None


def _require_message(message: bytes) -> bytes:
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("BIP-340 message must be bytes")
    return bytes(message)


def schnorr_public_key(private_scalar: int) -> bytes:
    """Return the 32-byte x-only BIP-340 public key."""
    if type(private_scalar) is not int or not 1 <= private_scalar < N:
        raise ValueError("private scalar must be in [1, N-1]")
    point = scalar_mult(private_scalar, G)
    if point is None:
        raise ArithmeticError("public-key multiplication returned infinity")
    return point[0].to_bytes(32, "big")


def schnorr_sign(message: bytes, private_scalar: int, aux_rand: bytes | None = None) -> bytes:
    """Sign a BIP-340 message of any length; use fresh auxiliary randomness by default."""
    message = _require_message(message)
    if type(private_scalar) is not int or not 1 <= private_scalar < N:
        raise ValueError("private scalar must be in [1, N-1]")
    if aux_rand is None:
        aux_rand = secrets.token_bytes(32)
    if not isinstance(aux_rand, bytes) or len(aux_rand) != 32:
        raise ValueError("aux_rand must be exactly 32 bytes")

    public_point = scalar_mult(private_scalar, G)
    if public_point is None:
        raise ArithmeticError("public-key multiplication returned infinity")
    adjusted_secret = private_scalar if public_point[1] % 2 == 0 else N - private_scalar
    public_x = public_point[0].to_bytes(32, "big")
    secret_bytes = adjusted_secret.to_bytes(32, "big")
    aux_hash = tagged_hash("BIP0340/aux", aux_rand)
    masked_secret = bytes(left ^ right for left, right in zip(secret_bytes, aux_hash))
    nonce_hash = tagged_hash("BIP0340/nonce", masked_secret + public_x + message)
    nonce = int.from_bytes(nonce_hash, "big") % N
    if nonce == 0:
        raise ArithmeticError("BIP-340 nonce is zero")
    nonce_point = scalar_mult(nonce, G)
    if nonce_point is None:
        raise ArithmeticError("BIP-340 nonce point is infinity")
    if nonce_point[1] & 1:
        nonce = N - nonce
        nonce_point = point_negate_affine(nonce_point)
    assert nonce_point is not None
    r_bytes = nonce_point[0].to_bytes(32, "big")
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", r_bytes + public_x + message), "big"
    ) % N
    signature = r_bytes + ((nonce + challenge * adjusted_secret) % N).to_bytes(32, "big")
    if not schnorr_verify(message, signature, public_x):
        raise ArithmeticError("self-verification of generated BIP-340 signature failed")
    return signature


def schnorr_verify(message: bytes, signature: bytes, public_key_x: bytes) -> bool:
    """Verify a BIP-340 signature over a message of any length against an x-only key."""
    if not isinstance(message, (bytes, bytearray)):
        return False
    message = bytes(message)
    if not isinstance(signature, bytes) or len(signature) != 64:
        return False
    if not isinstance(public_key_x, bytes) or len(public_key_x) != 32:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    public_point = _lift_x_even(int.from_bytes(public_key_x, "big"))
    if r >= P or s >= N or public_point is None:
        return False
    challenge = int.from_bytes(
        tagged_hash("BIP0340/challenge", signature[:32] + public_key_x + message), "big"
    ) % N
    left = scalar_mult(s, G)
    negative_challenge_point = scalar_mult((N - challenge) % N, public_point)
    candidate = point_add_affine(left, negative_challenge_point)
    return candidate is not None and candidate[1] % 2 == 0 and candidate[0] == r


__all__ = ["schnorr_public_key", "schnorr_sign", "schnorr_verify", "tagged_hash"]
