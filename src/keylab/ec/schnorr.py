"""BIP-340 Schnorr signing and verification primitives for secp256k1.

Messages may have any length, matching the 2022 revision of BIP-340 (official
test vectors 15-18). Bitcoin's Taproot signatures always sign a 32-byte
sighash, which is simply one particular message length.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence

from keylab.ec.secp256k1 import (
    G,
    N,
    P,
    Point,
    lift_x,
    multi_scalar_mult,
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


def _challenge(r_bytes: bytes, public_key_x: bytes, message: bytes) -> int:
    """BIP-340 challenge e = int(hash_BIP0340/challenge(r || P || m)) mod N."""
    return int.from_bytes(
        tagged_hash("BIP0340/challenge", r_bytes + public_key_x + message), "big"
    ) % N


def _parse_batch_item(item: object) -> tuple[Point, Point, int, int] | None:
    """Return (R, P, s, e) for a structurally valid BIP-340 triple, else None.

    ``item`` is ``(message, signature, public_key_x)`` as taken by
    :func:`schnorr_verify`. R is the even-y lift of r and P the even-y lift of the
    x-only key; a bad length, out-of-range r/s, or a coordinate that does not lift
    all yield None, which fails the whole batch (matching the single verifier).
    """
    if not (isinstance(item, (tuple, list)) and len(item) == 3):
        return None
    message, signature, public_key_x = item
    if not isinstance(message, (bytes, bytearray)):
        return None
    if not isinstance(signature, bytes) or len(signature) != 64:
        return None
    if not isinstance(public_key_x, bytes) or len(public_key_x) != 32:
        return None
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r >= P or s >= N:
        return None
    public_point = _lift_x_even(int.from_bytes(public_key_x, "big"))
    nonce_point = _lift_x_even(r)
    if public_point is None or nonce_point is None:
        return None
    e = _challenge(signature[:32], public_key_x, bytes(message))
    return nonce_point, public_point, s, e


def _batch_coefficients(count: int) -> list[int]:
    """Random batch coefficients in [1, N-1] from a CSPRNG, with the first fixed at 1.

    BIP-340 batch verification requires the first coefficient to be 1 and the rest
    unpredictable. ``secrets`` (a cryptographically secure source) is used directly;
    this never falls back to ``random.Random``.
    """
    coefficients = [1]
    coefficients.extend(secrets.randbelow(N - 1) + 1 for _ in range(count - 1))
    return coefficients


def schnorr_verify_batch(
    items: Sequence[tuple[bytes, bytes, bytes]],
    *,
    coefficients: Sequence[int] | None = None,
) -> bool:
    """Verify many BIP-340 signatures at once; equals the AND of individual verifies.

    Each item is ``(message, signature, public_key_x)``. Returns ``True`` iff every
    signature verifies. An empty batch is ``True``.

    With random coefficients a_i (a_1 = 1) the identity
    ``(sum a_i s_i) G == sum a_i R_i + sum a_i e_i P_i`` holds exactly when every
    signature is valid, and fails with overwhelming probability otherwise. It is
    checked as a single multi-scalar multiplication that must be the point at
    infinity.

    ``coefficients`` is for reproducible testing only: pass an explicit sequence
    (length ``len(items)``, first element 1, each in ``[1, N-1]``). Omit it in
    production, where coefficients come from :mod:`secrets`.
    """
    parsed: list[tuple[Point, Point, int, int]] = []
    for item in items:
        entry = _parse_batch_item(item)
        if entry is None:
            return False
        parsed.append(entry)
    if not parsed:
        return True

    if coefficients is None:
        coefficients = _batch_coefficients(len(parsed))
    else:
        coefficients = list(coefficients)
        if (len(coefficients) != len(parsed) or not coefficients or coefficients[0] != 1
                or any(type(a) is not int or not 1 <= a < N for a in coefficients)):
            raise ValueError("coefficients must be len(items) ints in [1, N-1] with the first equal to 1")

    terms: list[tuple[int, Point]] = []
    left_scalar = 0
    for (nonce_point, public_point, s, e), a in zip(parsed, coefficients, strict=True):
        left_scalar = (left_scalar + a * s) % N
        terms.append(((N - a) % N, nonce_point))          # -a_i * R_i
        terms.append(((N - a * e) % N, public_point))     # -a_i * e_i * P_i
    terms.append((left_scalar, G))                        # (sum a_i s_i) * G
    return multi_scalar_mult(terms) is None


__all__ = ["schnorr_public_key", "schnorr_sign", "schnorr_verify", "schnorr_verify_batch", "tagged_hash"]
