"""Recover an ECDSA private key from two signatures that reused one nonce.

Mathematical role: if two ECDSA signatures ``(r, s1)`` over ``z1`` and ``(r, s2)``
over ``z2`` share the same nonce ``k`` (hence the same ``r``), then
``k = (z1 - z2) / (s1 - s2)`` and ``d = (s1*k - z1) / r`` modulo ``N`` -- the
signing key falls out by linear algebra.

Scope boundary: this recovers a key **only** from signatures that genuinely
reused a nonce (the caller supplies the raw ``(r, s, z)`` values); it is not a
general key-recovery attack and does nothing against correct, unique-nonce
ECDSA. The signer must supply ``s`` as produced by ``s = k^-1 (z + r d)``; if the
values were low-S normalised, pass the matching representatives. See SECURITY.md.
"""

from __future__ import annotations

from keylab.ec.secp256k1 import G, N, Point, scalar_mult

__all__ = ["recover_private_key_from_nonce_reuse"]


def _is_scalar(value: object) -> bool:
    return type(value) is int and 0 < value < N


def recover_private_key_from_nonce_reuse(
    r: int, s1: int, z1: int, s2: int, z2: int, *, public_key: Point | None = None
) -> int | None:
    """Return the ECDSA private scalar ``d`` from a nonce-reuse pair, or ``None``.

    Both signatures share the nonce (same ``r``). Returns ``None`` when the inputs
    are inconsistent (e.g. ``s1 == s2``, or the recovered ``d`` fails the optional
    forward check ``d*G == public_key``) rather than returning a wrong guess.
    """
    for name, value in (("r", r), ("s1", s1), ("z1", z1), ("s2", s2), ("z2", z2)):
        if type(value) is not int:
            raise TypeError(f"{name} must be an integer")
    if not _is_scalar(r):
        raise ValueError("r must be in [1, N-1]")
    s_diff = (s1 - s2) % N
    if s_diff == 0:
        return None  # same s -> nonce not actually distinguishable; cannot solve
    k = (z1 - z2) * pow(s_diff, -1, N) % N
    if k == 0:
        return None
    d = (s1 * k - z1) * pow(r, -1, N) % N
    if not 1 <= d < N:
        return None
    if public_key is not None and scalar_mult(d, G) != public_key:
        return None  # forward verification failed -> not the key
    return d
