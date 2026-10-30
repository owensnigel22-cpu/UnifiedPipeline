"""ECDSA public-key recovery from a digest and signature (forensic utility)."""

from __future__ import annotations

from keylab.ec.secp256k1 import (
    G,
    N,
    P,
    Point,
    ecdsa_verify_digest,
    is_on_curve,
    point_add_affine,
    point_negate_affine,
    scalar_mult,
    y_from_x,
)


def recover_public_keys_from_signature(
    digest: bytes, signature: tuple[int, int]
) -> tuple[Point, ...]:
    """Return all valid secp256k1 public-key candidates for an ECDSA signature.

    This recovers public-key candidates only. It does not recover a private
    key, and callers should compare the candidates with the expected key or
    address context when available.
    """
    if type(digest) is not bytes or len(digest) != 32:
        raise ValueError("digest must be exactly 32 bytes")
    if len(signature) != 2:
        raise ValueError("signature must contain exactly r and s")
    r, s = signature
    if type(r) is not int or type(s) is not int or not (1 <= r < N and 1 <= s < N):
        raise ValueError("ECDSA signature values must be in [1, N-1]")

    z = int.from_bytes(digest, "big")
    negative_z_g = point_negate_affine(scalar_mult(z % N, G))
    inverse_r = pow(r, -1, N)
    candidates: list[Point] = []

    # x(R) can be r or r + n, when the latter is a canonical field element.
    for x in (r, r + N):
        if x >= P:
            continue
        try:
            y = y_from_x(x)
        except ValueError:
            continue
        for root in (y, (-y) % P):
            nonce_point: Point = (x, root)
            if not is_on_curve(nonce_point):
                continue
            candidate = scalar_mult(
                inverse_r,
                point_add_affine(scalar_mult(s, nonce_point), negative_z_g),
            )
            if candidate is not None and candidate not in candidates and ecdsa_verify_digest(
                digest, signature, candidate
            ):
                candidates.append(candidate)
    return tuple(candidates)


__all__ = ["recover_public_keys_from_signature"]
