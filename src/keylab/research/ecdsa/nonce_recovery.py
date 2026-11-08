"""Recover an ECDSA nonce from a signature when the private key is known.

Mathematical role: ECDSA sets ``s = k^-1 (h + r*d) mod n``, so given the signature
``(r, s)`` over hash ``h`` and the signer's own private key ``d``, the nonce is
``k = (h + r*d) * s^-1 mod n``. Pure algebra; no search.

Scope boundary: this recovers the nonce of *your own* signature (you supply the
private key ``d``); it is a determinism/debugging check and the kernel of why a
leaked or reused nonce is fatal, not an attack on someone else's key. See
SECURITY.md.
"""

from __future__ import annotations

from keylab.ec.secp256k1 import N

__all__ = ["recover_nonce_from_signature"]


def recover_nonce_from_signature(r: int, s: int, h: int, d: int, *, order: int = N) -> int:
    """Return the nonce ``k = (h + r*d) * s^-1 mod order`` for a known key ``d``.

    ``r``, ``s`` are the signature components, ``h`` the integer message hash, ``d``
    the signer's private scalar. Validated; raises on out-of-range inputs.
    """
    if type(order) is not int or order < 3:
        raise ValueError("order must be an int >= 3")
    for name, value in (("r", r), ("s", s), ("h", h), ("d", d)):
        if type(value) is not int:
            raise TypeError(f"{name} must be an integer")
    if not 1 <= r < order or not 1 <= s < order:
        raise ValueError("r and s must be in [1, order-1]")
    if not 1 <= d < order:
        raise ValueError("d must be in [1, order-1]")
    return (h + r * d) * pow(s, -1, order) % order
