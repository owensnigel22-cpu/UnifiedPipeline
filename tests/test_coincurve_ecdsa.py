"""Differential tests for explicit libsecp256k1 ECDSA operations."""

from __future__ import annotations

import hashlib

import pytest

from keylab.ec.coincurve_backend import (
    ecdsa_sign_digest_coincurve,
    ecdsa_sign_digest_python,
    ecdsa_verify_digest_coincurve,
)
from keylab.ec.secp256k1 import N, ecdsa_verify_digest, public_key_from_private_scalar


@pytest.mark.parametrize("index", range(8))
def test_coincurve_signatures_match_python_reference(index: int) -> None:
    pytest.importorskip("coincurve")
    private = (index * 0x123456789ABCDEF + 17) % (N - 1) + 1
    digest = hashlib.sha256(f"keylab-m10-ecdsa-{index}".encode()).digest()
    public = public_key_from_private_scalar(private, backend="python")
    reference = ecdsa_sign_digest_python(digest, private)
    native = ecdsa_sign_digest_coincurve(digest, private)
    assert native == reference
    assert ecdsa_verify_digest(digest, native, public)
    assert ecdsa_verify_digest_coincurve(digest, reference, public)
    assert ecdsa_verify_digest_coincurve(digest, (reference[0], N - reference[1]), public)


def test_native_verifier_rejects_malformed_signatures() -> None:
    pytest.importorskip("coincurve")
    public = public_key_from_private_scalar(1, backend="python")
    digest = b"\x00" * 32
    for signature in ((0, 1), (1, 0), (N, 1), (1, N), (True, 1), (1,), "bad"):
        assert not ecdsa_verify_digest_coincurve(digest, signature, public)  # type: ignore[arg-type]
    assert not ecdsa_verify_digest_coincurve(digest[:-1], (1, 1), public)
    assert not ecdsa_verify_digest_coincurve(digest, (1, 1), (1, 1))


def test_native_signer_validates_digest_and_private_scalar() -> None:
    pytest.importorskip("coincurve")
    with pytest.raises(ValueError, match="digest"):
        ecdsa_sign_digest_coincurve(b"short", 1)
    for private in (0, -1, N, N + 1, True):
        with pytest.raises(ValueError, match="private scalar"):
            ecdsa_sign_digest_coincurve(b"\x00" * 32, private)
