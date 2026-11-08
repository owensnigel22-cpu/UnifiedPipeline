"""BIP-340 Schnorr nonce-reuse key recovery (educational).

Signatures are built from scratch with a chosen key and a deliberately reused
nonce, then verified independently with the library's own `schnorr_verify`;
recovery must return a scalar whose x-only public key matches the signer's.
"""

from __future__ import annotations

from keylab.ec.schnorr import schnorr_public_key, schnorr_verify, tagged_hash
from keylab.ec.secp256k1 import G, N, point_negate_affine, scalar_mult
from keylab.research.schnorr_nonce_reuse import recover_private_key_from_schnorr_nonce_reuse


def _sign_fixed_nonce(d: int, k: int, message: bytes) -> tuple[bytes, bytes]:
    """Build a valid BIP-340 signature for key d with an explicit nonce k."""
    point = scalar_mult(d, G)
    adjusted_d = d if point[1] % 2 == 0 else N - d
    pub_x = point[0].to_bytes(32, "big")
    nonce_point = scalar_mult(k, G)
    if nonce_point[1] & 1:
        k = N - k
        nonce_point = point_negate_affine(nonce_point)
    r_bytes = nonce_point[0].to_bytes(32, "big")
    e = int.from_bytes(tagged_hash("BIP0340/challenge", r_bytes + pub_x + message), "big") % N
    s = (k + e * adjusted_d) % N
    sig = r_bytes + s.to_bytes(32, "big")
    assert schnorr_verify(message, sig, pub_x)  # independent validity check
    return sig, pub_x


def test_recovers_key_from_reused_schnorr_nonce() -> None:
    d = 0xDEAD_BEEF_0123_4567_89AB_CDEF_FEDC_BA98_7654_3210_1122_3344_5566_7788_99AA % N
    k = 0x0CAFE_1234_5678
    m1, m2 = b"schnorr message one", b"schnorr message two"
    sig1, pub_x = _sign_fixed_nonce(d, k, m1)
    sig2, _ = _sign_fixed_nonce(d, k, m2)
    assert sig1[:32] == sig2[:32]  # same R -> nonce reused
    rec = recover_private_key_from_schnorr_nonce_reuse(sig1, m1, sig2, m2, pub_x)
    assert rec is not None
    assert schnorr_public_key(rec) == pub_x  # independent forward verification


def test_different_nonce_returns_none() -> None:
    d = 1234567 % N
    sig1, pub_x = _sign_fixed_nonce(d, 111_131, b"a")
    sig2, _ = _sign_fixed_nonce(d, 222_263, b"b")  # different nonce -> different R
    assert recover_private_key_from_schnorr_nonce_reuse(sig1, b"a", sig2, b"b", pub_x) is None


def test_rejects_malformed_inputs() -> None:
    good, pub_x = _sign_fixed_nonce(99 % N, 7777, b"x")
    import pytest
    with pytest.raises(ValueError):
        recover_private_key_from_schnorr_nonce_reuse(good[:63], b"x", good, b"y", pub_x)
    with pytest.raises(ValueError):
        recover_private_key_from_schnorr_nonce_reuse(good, b"x", good, b"y", pub_x[:31])
