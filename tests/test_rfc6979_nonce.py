"""RFC 6979 nonce generation (ecdsa library) + algebraic nonce recovery.

Independent references: the ecdsa library's RFC 6979 nonce is cross-checked
against KeyLab's own rfc6979_nonce_from_digest; the recovered nonce is checked
against the exact k used to build the signature (and via r = (k*G).x mod N).
"""

from __future__ import annotations

import hashlib

import pytest

from keylab.ec.rfc6979 import generate_nonce
from keylab.ec.secp256k1 import G, N, rfc6979_nonce_from_digest, scalar_mult
from keylab.research.ecdsa import recover_nonce_from_signature


def _digest(msg: bytes) -> bytes:
    return hashlib.sha256(msg).digest()


def test_generate_nonce_matches_keylab_rfc6979() -> None:
    # Two independent RFC 6979 implementations must agree bit-for-bit.
    d = 0xC0FFEE_1234_5678_9ABC_DEF0_1122_3344_5566_7788_99AA_BBCC_DDEE_FF00_1234 % N or 7
    for msg in (b"", b"hello", b"the quick brown fox"):
        digest = _digest(msg)
        k_lib = generate_nonce(N, d, hashlib.sha256, digest)
        k_keylab = rfc6979_nonce_from_digest(d, digest)
        assert k_lib == k_keylab, f"RFC6979 mismatch for {msg!r}"
        assert 1 <= k_lib < N


def test_recover_nonce_yields_exact_k() -> None:
    # Build a raw (non-low-S) signature with the true RFC 6979 nonce, then recover it.
    d = 0x1234_5678_9ABC_DEF0 % N
    digest = _digest(b"sign me")
    z = int.from_bytes(digest, "big")
    k = generate_nonce(N, d, hashlib.sha256, digest)
    r = scalar_mult(k, G)[0] % N
    s = pow(k, -1, N) * (z + r * d) % N
    recovered = recover_nonce_from_signature(r, s, z, d)
    assert recovered == k  # the exact nonce
    assert scalar_mult(recovered, G)[0] % N == r  # forward-consistent


def test_recover_nonce_consistent_for_low_s_signature() -> None:
    # KeyLab's signer low-S-normalises s; the recovered k then matches +-k, both
    # of which give the same r. Assert the forward relation holds.
    from keylab.ec.secp256k1 import ecdsa_sign_digest
    d = 0xA11CE % N or 3
    digest = _digest(b"low-s message")
    z = int.from_bytes(digest, "big")
    r, s = ecdsa_sign_digest(digest, d)
    k = recover_nonce_from_signature(r, s, z, d)
    assert scalar_mult(k, G)[0] % N == r


def test_generate_nonce_rejects_bad_inputs() -> None:
    with pytest.raises(ValueError):
        generate_nonce(N, 0, hashlib.sha256, b"x")  # d out of range
    with pytest.raises(ValueError):
        generate_nonce(2, 1, hashlib.sha256, b"x")  # order too small
    with pytest.raises(TypeError):
        generate_nonce(N, 5, hashlib.sha256, "not bytes")  # type: ignore[arg-type]


def test_recover_nonce_rejects_bad_inputs() -> None:
    with pytest.raises(ValueError):
        recover_nonce_from_signature(0, 1, 1, 1)  # r out of range
    with pytest.raises(TypeError):
        recover_nonce_from_signature(1.0, 1, 1, 1)  # type: ignore[arg-type]
