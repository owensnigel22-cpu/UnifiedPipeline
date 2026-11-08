"""ECDSA biased-nonce (Hidden Number Problem) key recovery (educational).

Verified against the KNOWN planted key at a reduced modulus where the repo's
exact-rational LLL is fast: synthetic signatures are built with short nonces for
a chosen d, and recovery must return exactly d. (At secp256k1's 256-bit N the
same lattice is correct but the Fraction-based LLL is impractically slow -- a
documented performance limitation, see SEC_STATE_JOURNAL.md, not a correctness
gap.) Too-few-signatures must report insufficient, never a false positive.
"""

from __future__ import annotations

import random

import pytest

from keylab.research.ecdsa import recover_private_key_from_biased_nonces

_Q = 2147483647  # 2**31 - 1, prime


def _biased_signatures(d: int, m: int, nonce_bits: int, seed: int):
    rng = random.Random(seed)
    sigs = []
    for _ in range(m):
        k = rng.randrange(1, 1 << nonce_bits)
        r = rng.randrange(1, _Q)
        z = rng.randrange(1, _Q)
        s = pow(k, -1, _Q) * (z + r * d) % _Q
        sigs.append((r, s, z))
    return sigs


def test_recovers_planted_key_from_biased_nonces() -> None:
    rng = random.Random(11)
    for trial in range(3):
        d = rng.randrange(1, _Q)
        sigs = _biased_signatures(d, m=7, nonce_bits=16, seed=trial)
        result = recover_private_key_from_biased_nonces(sigs, nonce_bits=16, order=_Q)
        assert result.sufficient
        assert result.recovered == d  # independent: the planted key


def test_insufficient_signatures_reports_not_a_guess() -> None:
    d = 123456789
    sigs = _biased_signatures(d, m=2, nonce_bits=16, seed=0)  # too few for the bias
    result = recover_private_key_from_biased_nonces(sigs, nonce_bits=16, order=_Q)
    assert result.sufficient is False
    assert result.recovered is None


def test_rejects_bad_parameters() -> None:
    sigs = _biased_signatures(42, m=7, nonce_bits=16, seed=1)
    with pytest.raises(ValueError, match="order"):
        recover_private_key_from_biased_nonces(sigs, nonce_bits=16, order=2)
    with pytest.raises(ValueError, match="nonce_bits"):
        recover_private_key_from_biased_nonces(sigs, nonce_bits=0, order=_Q)
    with pytest.raises(ValueError, match="nonce_bits"):
        recover_private_key_from_biased_nonces(sigs, nonce_bits=_Q.bit_length(), order=_Q)
