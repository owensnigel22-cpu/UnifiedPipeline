import hashlib

import pytest

from keylab.ec.ecdsa_recovery import recover_public_keys_from_signature
from keylab.ec.secp256k1 import (
    N,
    ecdsa_sign_digest,
    is_high_s_signature,
    public_key_from_private_scalar,
)


def test_ecdsa_signature_recovers_its_public_key_candidate() -> None:
    digest = hashlib.sha256(b"public-key recovery known-answer fixture").digest()
    private_scalar = 0x123456789ABCDEF
    public_key = public_key_from_private_scalar(private_scalar, backend="python")
    signature = ecdsa_sign_digest(digest, private_scalar, backend="python")

    candidates = recover_public_keys_from_signature(digest, signature)
    assert public_key in candidates
    assert candidates


def test_ecdsa_public_key_recovery_rejects_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="digest"):
        recover_public_keys_from_signature(b"short", (1, 1))
    with pytest.raises(ValueError, match="signature values"):
        recover_public_keys_from_signature(bytes(32), (0, 1))


def test_high_s_detection_identifies_malleable_form() -> None:
    assert not is_high_s_signature((1, 1))
    assert is_high_s_signature((1, N - 1))
    with pytest.raises(ValueError):
        is_high_s_signature((0, 1))
