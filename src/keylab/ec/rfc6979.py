"""RFC 6979 deterministic nonce generation via the reviewed ``ecdsa`` library.

Mathematical role: return the deterministic per-message ECDSA nonce ``k`` that
RFC 6979 prescribes for a private scalar ``d`` and a message hash ``h``, delegating
to :func:`ecdsa.rfc6979.generate_k` so the value can be cross-checked against
KeyLab's own :func:`keylab.ec.secp256k1.rfc6979_nonce_from_digest`.

Scope boundary: this computes a nonce from values the caller already holds (the
private key and the message hash); it is a deterministic-signing building block
and a cross-check oracle, not an attack. See SECURITY.md.
"""

from __future__ import annotations

from collections.abc import Callable

from ecdsa.rfc6979 import generate_k as _generate_k

from keylab.ec.secp256k1 import N

__all__ = ["generate_nonce"]


def generate_nonce(
    order: int,
    d: int,
    hash_func: Callable[[bytes], object],
    h: bytes,
) -> int:
    """Return the RFC 6979 nonce ``k`` for private scalar ``d`` and message hash ``h``.

    ``order`` is the curve order (``N`` for secp256k1), ``hash_func`` the hash
    constructor (e.g. ``hashlib.sha256``) used by the HMAC-DRBG, and ``h`` the
    message digest bytes. Validated inputs; delegates to ``ecdsa.rfc6979``.
    """
    if type(order) is not int or order < 3:
        raise ValueError("order must be an int >= 3")
    if type(d) is not int or not 1 <= d < order:
        raise ValueError("d must be an int in [1, order-1]")
    if not isinstance(h, (bytes, bytearray)):
        raise TypeError("h must be bytes (the message hash)")
    k = _generate_k(order, d, hash_func, bytes(h))
    if not 1 <= k < order:  # ecdsa.generate_k already guarantees this; assert the contract
        raise ArithmeticError("RFC 6979 produced an out-of-range nonce")
    return k


def _default_order() -> int:
    return N
