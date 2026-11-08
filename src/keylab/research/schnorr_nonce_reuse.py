"""Recover a BIP-340 (Schnorr) private key from two signatures that reused a nonce.

Mathematical role: BIP-340 signs ``s = k + e*d`` with ``e`` the challenge and ``k``
the nonce behind ``R``. Two signatures over ``m1, m2`` that share the nonce (hence
the same ``R``) give ``s1 - s2 = (e1 - e2) * d``, so ``d = (s1 - s2) / (e1 - e2)``
modulo ``N``. The recovered scalar is the even-``y`` (BIP-340-adjusted) secret, a
valid signing scalar for the x-only public key.

Scope boundary: recovers a key **only** from genuine nonce reuse (same ``R`` across
two signatures the caller supplies); it does nothing against correct BIP-340
signing, which derives a fresh nonce per message. Teaching aid; see SECURITY.md.
"""

from __future__ import annotations

from keylab.ec.schnorr import schnorr_public_key, tagged_hash
from keylab.ec.secp256k1 import N

__all__ = ["recover_private_key_from_schnorr_nonce_reuse"]


def _challenge(r_bytes: bytes, public_key_x: bytes, message: bytes) -> int:
    return int.from_bytes(tagged_hash("BIP0340/challenge", r_bytes + public_key_x + message), "big") % N


def recover_private_key_from_schnorr_nonce_reuse(
    signature1: bytes, message1: bytes, signature2: bytes, message2: bytes, public_key_x: bytes
) -> int | None:
    """Return the BIP-340 private scalar from a nonce-reuse pair, or ``None``.

    Each signature is 64 bytes (``R_x`` || ``s``). Returns ``None`` when the two
    signatures do not actually share a nonce (different ``R_x``), the challenges
    coincide, or the recovered scalar fails ``schnorr_public_key(d) == public_key_x``.
    """
    for name, sig in (("signature1", signature1), ("signature2", signature2)):
        if not isinstance(sig, bytes) or len(sig) != 64:
            raise ValueError(f"{name} must be 64 bytes (R_x || s)")
    if not isinstance(public_key_x, bytes) or len(public_key_x) != 32:
        raise ValueError("public_key_x must be 32 bytes")
    for name, msg in (("message1", message1), ("message2", message2)):
        if not isinstance(msg, (bytes, bytearray)):
            raise TypeError(f"{name} must be bytes")

    r1, r2 = signature1[:32], signature2[:32]
    if r1 != r2:
        return None  # different R -> not a reused nonce
    s1 = int.from_bytes(signature1[32:], "big")
    s2 = int.from_bytes(signature2[32:], "big")
    e_diff = (_challenge(r1, public_key_x, bytes(message1)) - _challenge(r2, public_key_x, bytes(message2))) % N
    if e_diff == 0:
        return None
    d = (s1 - s2) * pow(e_diff, -1, N) % N
    if not 1 <= d < N:
        return None
    if schnorr_public_key(d) != public_key_x:  # forward verification
        return None
    return d
