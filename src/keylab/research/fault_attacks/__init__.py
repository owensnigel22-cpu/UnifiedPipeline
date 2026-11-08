"""Simulated Bellcore fault attacks (RSA-CRT and ECDSA).

Real Bellcore attacks require physical fault injection (voltage/clock glitching);
these functions SIMULATE the mathematical consequence by corrupting an
intermediate value in software, then recover the key from a correct/faulty
signature pair. They recover nothing from correctly-computed output. The
mitigation: verify every signature before releasing it. See
docs/research/fault_attacks.md and SECURITY.md.
"""

from __future__ import annotations

from keylab.research.fault_attacks.ecdsa_fault import (
    ecdsa_sign_with_fault,
    recover_private_key_from_ecdsa_fault,
)
from keylab.research.fault_attacks.rsa_crt import (
    CRTFaultResult,
    recover_primes_from_crt_fault,
    rsa_crt_sign,
)

__all__ = [
    "CRTFaultResult",
    "ecdsa_sign_with_fault",
    "recover_primes_from_crt_fault",
    "recover_private_key_from_ecdsa_fault",
    "rsa_crt_sign",
]
