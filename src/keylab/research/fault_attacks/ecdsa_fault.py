"""Bellcore ECDSA fault attack (simulated).

Mathematical role: a correct ECDSA signature ``(r, s)`` and a faulty ``(r_f, s_f)``
over the same digest with the **same nonce** ``k`` (a fault glitched the point
``R = kG`` so ``r_f != r`` while the signer still used the correct ``k`` in
``s_f = k^{-1}(z + r_f d)``) give two linear equations in ``(k, d)``. Eliminating
``k``:  ``d = z(s - s_f) * (s_f*r - s*r_f)^{-1} mod n`` -- the private key by a 2x2
solve, with no brute force and no knowledge of the fault magnitude.

Scope boundary: :func:`ecdsa_sign_with_fault` corrupts the scalar-multiplication
result *in software* to **simulate the mathematical consequence** of a physical
glitch; it performs no physical attack and recovers nothing from two correct
signatures. Mitigation: verify the signature before output (KeyLab's stock signer
already self-verifies). See docs/research/fault_attacks.md and SECURITY.md.
"""

from __future__ import annotations

from keylab.ec.secp256k1 import G, N, Point, rfc6979_nonce_from_digest, scalar_mult

__all__ = ["ecdsa_sign_with_fault", "recover_private_key_from_ecdsa_fault"]


def ecdsa_sign_with_fault(
    digest: bytes, d: int, *, fault_delta: int | None = None
) -> tuple[int, int]:
    """Sign ``digest`` under key ``d`` (raw, no low-S), optionally glitching the point.

    The nonce ``k`` is the deterministic RFC 6979 value, so a correct call and a
    faulty call over the same digest share ``k``. With ``fault_delta`` set, the
    scalar multiplication is glitched (``R`` computed as ``(k + fault_delta)*G``) so
    ``r`` is corrupted, while the correct ``k`` is still used in ``s`` -- exactly the
    Bellcore fault condition.
    """
    if type(digest) is not bytes or len(digest) != 32:
        raise ValueError("digest must be exactly 32 bytes")
    if type(d) is not int or not 1 <= d < N:
        raise ValueError("d must be an int in [1, N-1]")
    if fault_delta is not None and type(fault_delta) is not int:
        raise TypeError("fault_delta must be an int or None")

    k = rfc6979_nonce_from_digest(d, digest)
    z = int.from_bytes(digest, "big")
    scalar = k if fault_delta is None else (k + fault_delta) % N  # glitched scalar mult
    point = scalar_mult(scalar, G)
    if point is None:
        raise ArithmeticError("scalar multiplication returned the identity")
    r = point[0] % N
    s = pow(k, -1, N) * (z + r * d) % N  # the SAME correct k is used in s
    if r == 0 or s == 0:
        raise ArithmeticError("degenerate signature; choose another digest")
    return r, s


def recover_private_key_from_ecdsa_fault(
    digest: bytes, r: int, s: int, r_faulty: int, s_faulty: int, *, public_key: Point | None = None
) -> int | None:
    """Recover ``d`` from a correct ``(r, s)`` and a same-nonce faulty ``(r_f, s_f)``.

    ``d = z(s - s_f) * (s_f*r - s*r_f)^{-1} mod n``. Returns ``None`` (never a wrong
    key) when the denominator is zero (e.g. two correct signatures) or the optional
    forward check ``d*G == public_key`` fails.
    """
    if type(digest) is not bytes or len(digest) != 32:
        raise ValueError("digest must be exactly 32 bytes")
    for name, value in (("r", r), ("s", s), ("r_faulty", r_faulty), ("s_faulty", s_faulty)):
        if type(value) is not int:
            raise TypeError(f"{name} must be an integer")
        if not 1 <= value < N:
            raise ValueError(f"{name} must be in [1, N-1]")
    z = int.from_bytes(digest, "big")
    denom = (s_faulty * r - s * r_faulty) % N
    if denom == 0:
        return None
    d = z * (s - s_faulty) % N * pow(denom, -1, N) % N
    if not 1 <= d < N:
        return None
    if public_key is not None and scalar_mult(d, G) != public_key:
        return None
    return d
