import pytest

from keylab.crypto import hkdf


def test_hkdf_rfc5869_sha256_test_case_1() -> None:
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    assert hkdf(ikm, 42, salt=salt, info=info) == expected


def test_hkdf_supports_sha512_and_zero_length() -> None:
    # Fixed SHA-512 output vector, independently generated with OpenSSL HKDF.
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex(
        "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9"
        "fc7fe92c1481579338da362cb8d9f925d7cb"
    )
    assert hkdf(ikm, len(expected), salt=salt, info=info, hash_name="sha512") == expected
    assert hkdf(b"input", 0) == b""


def test_hkdf_rejects_invalid_parameters() -> None:
    with pytest.raises(ValueError, match="length"):
        hkdf(b"x", -1)
    with pytest.raises(ValueError, match="255"):
        hkdf(b"x", 255 * 32 + 1)
    with pytest.raises(ValueError, match="hash_name"):
        hkdf(b"x", 1, hash_name="sha1")
