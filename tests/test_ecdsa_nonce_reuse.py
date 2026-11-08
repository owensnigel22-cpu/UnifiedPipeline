"""ECDSA nonce-reuse key recovery (educational).

Verified against the KNOWN planted key: signatures are built from scratch with a
chosen d and a deliberately reused k, and recovery must return that exact d
(forward-verified d*G == public key). Inconsistent inputs must yield None, not a
wrong guess.
"""

from __future__ import annotations

import hashlib

import pytest

from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.research.ecdsa import recover_private_key_from_nonce_reuse


def _z(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N


def _reused_nonce_pair(d: int, k: int, m1: bytes, m2: bytes):
    """Build two raw ECDSA signatures that share nonce k (no low-S normalisation)."""
    r = scalar_mult(k, G)[0] % N
    z1, z2 = _z(m1), _z(m2)
    s1 = pow(k, -1, N) * (z1 + r * d) % N
    s2 = pow(k, -1, N) * (z2 + r * d) % N
    return r, s1, z1, s2, z2


def test_recovers_planted_key_and_forward_verifies() -> None:
    d = 0xA11CE_BEEF_1234_5678_9ABC_DEF0_0F1E_2D3C_4B5A_6978_8796_A5B4_C3D2_E1F0_1122
    d %= N
    pub = scalar_mult(d, G)
    r, s1, z1, s2, z2 = _reused_nonce_pair(d, 0x1337_C0DE, b"first message", b"second message")
    rec = recover_private_key_from_nonce_reuse(r, s1, z1, s2, z2, public_key=pub)
    assert rec == d
    assert scalar_mult(rec, G) == pub  # independent forward verification


def test_recovers_without_public_key_arg() -> None:
    d = 1234567
    r, s1, z1, s2, z2 = _reused_nonce_pair(d, 999_983, b"m1", b"m2")
    assert recover_private_key_from_nonce_reuse(r, s1, z1, s2, z2) == d


def test_same_s_returns_none() -> None:
    d = 42
    r, s1, z1, _, _ = _reused_nonce_pair(d, 777, b"x", b"x")  # identical message -> s1 == s2
    assert recover_private_key_from_nonce_reuse(r, s1, z1, s1, z1) is None


def test_wrong_public_key_returns_none_not_guess() -> None:
    d = 555
    r, s1, z1, s2, z2 = _reused_nonce_pair(d, 888, b"a", b"b")
    other_pub = scalar_mult(556, G)  # not d's key
    assert recover_private_key_from_nonce_reuse(r, s1, z1, s2, z2, public_key=other_pub) is None


def test_rejects_bad_inputs() -> None:
    with pytest.raises(TypeError):
        recover_private_key_from_nonce_reuse(1.0, 2, 3, 4, 5)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        recover_private_key_from_nonce_reuse(0, 2, 3, 4, 5)  # r out of range
