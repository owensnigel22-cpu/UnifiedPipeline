import hashlib
import hmac

import pytest

from keylab.hashes.mac import hmac_sha256, verify_hmac_sha256


def test_hmac_sha256_matches_standard_library() -> None:
    key, message = b"shared secret", b"authenticate this message"
    assert hmac_sha256(key, message) == hmac.digest(key, message, hashlib.sha256)


def test_verify_hmac_sha256_accepts_only_matching_tag() -> None:
    key, message = b"key", b"message"
    tag = hmac_sha256(key, message)

    assert verify_hmac_sha256(key, message, tag)
    assert not verify_hmac_sha256(key, message + b"!", tag)
    assert not verify_hmac_sha256(key, message, bytes(32))
    assert not verify_hmac_sha256(key, message, b"short")


@pytest.mark.parametrize("key,message", [(b"", b""), (bytes(range(100)), b"long key")])
def test_hmac_sha256_handles_empty_and_long_keys(key: bytes, message: bytes) -> None:
    assert hmac_sha256(key, message) == hmac.new(key, message, hashlib.sha256).digest()
