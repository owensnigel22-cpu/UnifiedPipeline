"""Simulated Bellcore CRT-RSA fault attack (educational).

Verified against the PLANTED key: a keypair is generated, a message is CRT-signed
correctly and with a p-branch fault, and recovery must return the planted primes
and private exponent. The correct signature is independently checked to verify
(s^e mod n == m). Negative cases return None, never a wrong factor.
"""

from __future__ import annotations

import hashlib
import math

import pytest

from keylab.advanced_suite import _generate_prime
from keylab.research.fault_attacks import recover_primes_from_crt_fault, rsa_crt_sign

_E = 65537


def _keypair(bits: int = 256):
    p = _generate_prime(bits, _E)
    q = _generate_prime(bits, _E)
    while q == p:
        q = _generate_prime(bits, _E)
    n = p * q
    lam = math.lcm(p - 1, q - 1)
    d = pow(_E, -1, lam)
    return p, q, n, d, d % (p - 1), d % (q - 1), pow(q, -1, p)


def test_recovers_planted_key_from_crt_fault() -> None:
    p, q, n, d, d_p, d_q, q_inv = _keypair()
    message = int.from_bytes(hashlib.sha256(b"m6 bellcore crt").digest(), "big") % n

    correct = rsa_crt_sign(message, p, q, d_p, d_q, q_inv)
    assert pow(correct, _E, n) == message  # independent: the correct signature verifies

    faulty = rsa_crt_sign(message, p, q, d_p, d_q, q_inv, fault_branch="p", fault_delta=0xBADBEEF)
    assert faulty != correct

    result = recover_primes_from_crt_fault(correct, faulty, n, _E)
    assert result is not None
    assert {result.p, result.q} == {p, q}
    assert result.private_exponent == d
    assert result.p * result.q == n


def test_fault_in_q_branch_also_factors() -> None:
    p, q, n, _d, d_p, d_q, q_inv = _keypair()
    message = int.from_bytes(hashlib.sha256(b"q branch").digest(), "big") % n
    correct = rsa_crt_sign(message, p, q, d_p, d_q, q_inv)
    faulty = rsa_crt_sign(message, p, q, d_p, d_q, q_inv, fault_branch="q", fault_delta=7)
    result = recover_primes_from_crt_fault(correct, faulty, n, _E)
    assert result is not None and {result.p, result.q} == {p, q}


def test_two_correct_signatures_recover_nothing() -> None:
    p, q, n, _d, d_p, d_q, q_inv = _keypair()
    message = int.from_bytes(hashlib.sha256(b"no fault").digest(), "big") % n
    correct = rsa_crt_sign(message, p, q, d_p, d_q, q_inv)
    assert recover_primes_from_crt_fault(correct, correct, n, _E) is None  # diff == 0


def test_trivial_gcd_returns_none() -> None:
    # two unrelated numbers whose difference is coprime to n -> no factor
    _p, _q, n, *_ = _keypair()
    assert recover_primes_from_crt_fault(5, 8, n, _E) is None  # gcd(3, n) == 1


def test_rejects_bad_inputs() -> None:
    with pytest.raises(TypeError):
        rsa_crt_sign(1.0, 3, 5, 1, 1, 1)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        rsa_crt_sign(1, 3, 5, 1, 1, 1, fault_branch="x")
    with pytest.raises(TypeError):
        recover_primes_from_crt_fault(1.0, 2, 15)  # type: ignore[arg-type]
