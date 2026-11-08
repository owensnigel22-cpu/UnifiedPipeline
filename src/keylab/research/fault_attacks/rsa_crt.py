"""Bellcore CRT-RSA fault attack (simulated).

Mathematical role: CRT-RSA signing computes ``s`` from the two half-exponentiations
``s_p = m^{d_p} mod p`` and ``s_q = m^{d_q} mod q``. If a fault corrupts the
p-branch, the faulty ``s'`` satisfies ``s' = s (mod q)`` but ``s' != s (mod p)``, so
``q = gcd(s - s', n)`` and ``p = n / q`` -- one faulty signature factors the modulus.

Scope boundary: :func:`rsa_crt_sign` corrupts an intermediate value *in software*
to **simulate the mathematical consequence** of a physical fault (voltage/clock
glitch); it performs no physical attack and recovers nothing from two correct
signatures. The mitigation it motivates: verify ``s^e mod n == m`` before output.
See docs/research/fault_attacks.md and SECURITY.md.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

__all__ = ["CRTFaultResult", "recover_primes_from_crt_fault", "rsa_crt_sign"]


@dataclass(frozen=True)
class CRTFaultResult:
    """Primes and private exponent recovered from a single faulty CRT-RSA signature."""

    p: int
    q: int
    private_exponent: int


def rsa_crt_sign(
    message: int, p: int, q: int, d_p: int, d_q: int, q_inv: int,
    *, fault_branch: str | None = None, fault_delta: int = 1,
) -> int:
    """CRT-RSA sign ``message`` under primes ``p, q`` (Garner recombination).

    With ``fault_branch`` in ``{'p','q'}`` a software fault adds ``fault_delta`` to
    that branch's half-signature before recombination -- a stand-in for a physical
    glitch. ``None`` (default) signs correctly.
    """
    for name, value in (("p", p), ("q", q), ("d_p", d_p), ("d_q", d_q), ("q_inv", q_inv),
                        ("message", message), ("fault_delta", fault_delta)):
        if type(value) is not int:
            raise TypeError(f"{name} must be an integer")
    if p < 2 or q < 2:
        raise ValueError("p and q must be primes >= 2")
    if fault_branch not in (None, "p", "q"):
        raise ValueError("fault_branch must be None, 'p', or 'q'")

    s_p = pow(message % p, d_p, p)
    s_q = pow(message % q, d_q, q)
    if fault_branch == "p":
        s_p = (s_p + fault_delta) % p
    elif fault_branch == "q":
        s_q = (s_q + fault_delta) % q
    h = (q_inv * (s_p - s_q)) % p
    return s_q + h * q


def recover_primes_from_crt_fault(
    correct_sig: int, faulty_sig: int, n: int, e: int = 65537
) -> CRTFaultResult | None:
    """Recover ``(p, q, d)`` from a correct and a single-branch-faulty CRT signature.

    Returns ``None`` (never a wrong factor) when the pair is not a genuine
    single-branch fault -- i.e. ``gcd(|s - s'|, n)`` is trivial (1 or n), the split
    does not multiply back to ``n``, or ``e`` is not invertible mod ``lcm(p-1, q-1)``.
    """
    for name, value in (("correct_sig", correct_sig), ("faulty_sig", faulty_sig), ("n", n), ("e", e)):
        if type(value) is not int:
            raise TypeError(f"{name} must be an integer")
    if n < 2 or e < 2:
        raise ValueError("n and e must be >= 2")
    diff = abs(correct_sig - faulty_sig)
    if diff == 0:
        return None  # two correct (identical) signatures leak nothing
    q = math.gcd(diff, n)
    if q in (1, n):
        return None  # not a single-branch fault
    p = n // q
    if p * q != n:
        return None
    lam = math.lcm(p - 1, q - 1)
    try:
        d = pow(e, -1, lam)
    except ValueError:
        return None
    return CRTFaultResult(p=p, q=q, private_exponent=d)
