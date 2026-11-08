"""Simulated Bellcore ECDSA fault attack (educational).

Verified against the PLANTED key: a keypair signs a digest correctly and with a
scalar-multiplication fault (same nonce), and recovery must return exactly d
(forward-verified d*G == public key). Negative cases return None, never a wrong key.
"""

from __future__ import annotations

import hashlib

import pytest

from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.research.fault_attacks import (
    ecdsa_sign_with_fault,
    recover_private_key_from_ecdsa_fault,
)

_DIGEST = hashlib.sha256(b"m6 ecdsa fault message").digest()


def test_recovers_planted_key_from_ecdsa_fault() -> None:
    d = 0xA11CE_BEEF_1234_5678_9ABC_DEF0_0F1E_2D3C_4B5A_6978 % N
    pub = scalar_mult(d, G)

    correct = ecdsa_sign_with_fault(_DIGEST, d)
    faulty = ecdsa_sign_with_fault(_DIGEST, d, fault_delta=0xBADBEEF)
    assert correct[0] != faulty[0]  # the glitched R gives a different r

    recovered = recover_private_key_from_ecdsa_fault(_DIGEST, *correct, *faulty, public_key=pub)
    assert recovered == d
    assert scalar_mult(recovered, G) == pub  # independent forward verification


@pytest.mark.parametrize("d", [1, 2, 3, 1234567, (N - 1) % N or 1])
def test_recovery_across_several_keys(d) -> None:
    correct = ecdsa_sign_with_fault(_DIGEST, d)
    faulty = ecdsa_sign_with_fault(_DIGEST, d, fault_delta=99)
    assert recover_private_key_from_ecdsa_fault(_DIGEST, *correct, *faulty) == d


def test_two_correct_signatures_recover_nothing() -> None:
    d = 777_777
    correct = ecdsa_sign_with_fault(_DIGEST, d)
    # same nonce, same r -> denominator s*r - s*r == 0 -> None
    assert recover_private_key_from_ecdsa_fault(_DIGEST, *correct, *correct) is None


def test_rejects_bad_inputs() -> None:
    with pytest.raises(ValueError):
        ecdsa_sign_with_fault(b"short", 5)            # bad digest length
    with pytest.raises(ValueError):
        ecdsa_sign_with_fault(_DIGEST, 0)             # d out of range
    with pytest.raises(ValueError):
        recover_private_key_from_ecdsa_fault(_DIGEST, 0, 1, 1, 1)  # r out of range
    with pytest.raises(TypeError):
        recover_private_key_from_ecdsa_fault(_DIGEST, 1.0, 1, 1, 1)  # type: ignore[arg-type]
