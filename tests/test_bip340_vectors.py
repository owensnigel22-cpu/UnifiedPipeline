"""Official BIP-340 test vectors 0-18, including variable-length messages."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from keylab import advanced_suite
from keylab.ec import schnorr
from keylab.ec.schnorr import schnorr_public_key, schnorr_sign, schnorr_verify
from keylab.ec.secp256k1 import N, P

with (Path(__file__).parent / "vectors" / "bip340_test_vectors.csv").open(encoding="utf-8") as _csv:
    VECTORS = list(csv.DictReader(_csv))


def test_fixture_contains_all_nineteen_official_vectors() -> None:
    assert [int(row["index"]) for row in VECTORS] == list(range(19))
    assert sum(row["verification result"] == "TRUE" for row in VECTORS) == 9
    assert sum(row["verification result"] == "FALSE" for row in VECTORS) == 10


def _coincurve_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Treat native parser errors for malformed x-only inputs as verification failure."""
    coincurve = pytest.importorskip("coincurve")
    try:
        return coincurve.keys.PublicKeyXOnly(public_key).verify(signature, message)
    except (TypeError, ValueError):
        return False


@pytest.mark.parametrize("row", VECTORS, ids=lambda row: f"vector{row['index']}")
def test_bip340_official_vector(row: dict[str, str]) -> None:
    public_key = bytes.fromhex(row["public key"])
    message = bytes.fromhex(row["message"])
    signature = bytes.fromhex(row["signature"])
    expected = row["verification result"] == "TRUE"

    if row["secret key"]:
        secret = int(row["secret key"], 16)
        assert schnorr_public_key(secret) == public_key
        assert schnorr_sign(message, secret, bytes.fromhex(row["aux_rand"])) == signature
    assert schnorr_verify(message, signature, public_key) is expected


@pytest.mark.parametrize("row", VECTORS, ids=lambda row: f"libsecp256k1-vector{row['index']}")
def test_bip340_official_vectors_match_libsecp256k1(row: dict[str, str]) -> None:
    public_key = bytes.fromhex(row["public key"])
    message = bytes.fromhex(row["message"])
    signature = bytes.fromhex(row["signature"])
    expected = row["verification result"] == "TRUE"

    keylab_result = schnorr_verify(message, signature, public_key)
    native_result = _coincurve_verify(message, signature, public_key)

    assert keylab_result is expected, f"KeyLab disagrees with official vector {row['index']}"
    assert native_result is expected, f"libsecp256k1 disagrees with official vector {row['index']}"
    assert keylab_result is native_result, (
        f"vector {row['index']} ({row['comment']}): "
        f"KeyLab={keylab_result}, libsecp256k1={native_result}"
    )


@pytest.mark.parametrize("message", [bytes(32), bytes(range(32)), bytes.fromhex("ff" * 32)])
@pytest.mark.parametrize("secret", [1, N - 1])
def test_generated_bip340_signatures_match_libsecp256k1(
    message: bytes,
    secret: int,
) -> None:
    coincurve = pytest.importorskip("coincurve")
    auxiliary_randomness = bytes(range(32))
    secret_bytes = secret.to_bytes(32, "big")
    keylab_public_key = schnorr_public_key(secret)
    keylab_signature = schnorr_sign(message, secret, auxiliary_randomness)
    native_key = coincurve.PrivateKey(secret_bytes)
    native_public_key = coincurve.keys.PublicKeyXOnly.from_secret(secret_bytes)
    native_signature = native_key.sign_schnorr(message, auxiliary_randomness)

    assert keylab_public_key == native_public_key.format()
    assert keylab_signature == native_signature
    assert schnorr_verify(message, keylab_signature, keylab_public_key)
    assert native_public_key.verify(keylab_signature, message)


@pytest.mark.parametrize("private_scalar", [0, -1, N, N + 1, True])
def test_bip340_signing_and_public_key_reject_invalid_scalars(private_scalar: int) -> None:
    with pytest.raises(ValueError, match="private scalar"):
        schnorr_public_key(private_scalar)
    with pytest.raises(ValueError, match="private scalar"):
        schnorr_sign(b"message", private_scalar, bytes(32))


def _flip_bit(value: bytes, bit_index: int) -> bytes:
    result = bytearray(value)
    result[bit_index // 8] ^= 1 << (7 - bit_index % 8)
    return bytes(result)


@pytest.mark.parametrize("field", ["message", "signature", "public_key"])
@pytest.mark.parametrize("bit_index", [0, 127, 255])
def test_single_bit_mutations_are_rejected_by_both_verifiers(
    field: str,
    bit_index: int,
) -> None:
    row = VECTORS[0]
    message = bytes.fromhex(row["message"])
    signature = bytes.fromhex(row["signature"])
    public_key = bytes.fromhex(row["public key"])
    if field == "message":
        message = _flip_bit(message, bit_index)
    elif field == "signature":
        signature = _flip_bit(signature, bit_index)
    else:
        public_key = _flip_bit(public_key, bit_index)

    assert not schnorr_verify(message, signature, public_key)
    assert not _coincurve_verify(message, signature, public_key)


@pytest.mark.parametrize("signature", [b"", bytes(63), bytes(65)])
def test_invalid_signature_lengths_are_rejected_by_both_verifiers(signature: bytes) -> None:
    row = VECTORS[0]
    message = bytes.fromhex(row["message"])
    public_key = bytes.fromhex(row["public key"])

    assert not schnorr_verify(message, signature, public_key)
    assert not _coincurve_verify(message, signature, public_key)


@pytest.mark.parametrize("public_key", [b"", bytes(31), bytes(33)])
def test_invalid_public_key_lengths_are_rejected_by_both_verifiers(public_key: bytes) -> None:
    row = VECTORS[0]
    message = bytes.fromhex(row["message"])
    signature = bytes.fromhex(row["signature"])

    assert not schnorr_verify(message, signature, public_key)
    assert not _coincurve_verify(message, signature, public_key)


@pytest.mark.parametrize("public_key", [P.to_bytes(32, "big"), bytes.fromhex("ff" * 32)])
def test_invalid_x_only_public_keys_are_rejected_by_both_verifiers(public_key: bytes) -> None:
    row = VECTORS[0]
    message = bytes.fromhex(row["message"])
    signature = bytes.fromhex(row["signature"])

    assert not schnorr_verify(message, signature, public_key)
    assert not _coincurve_verify(message, signature, public_key)


@pytest.mark.parametrize("length", [0, 1, 17, 31, 33, 100, 1000])
def test_bip340_round_trips_arbitrary_message_lengths(length: int) -> None:
    secret = 0x0340034003400340034003400340034003400340034003400340034003400340
    message = bytes(range(256)) * (length // 256) + bytes(range(length % 256))
    signature = schnorr_sign(message, secret, bytes(32))
    public_key = schnorr_public_key(secret)
    assert schnorr_verify(message, signature, public_key)
    assert not schnorr_verify(message + b"\x00", signature, public_key)


def test_bip340_message_length_is_bound_into_the_challenge() -> None:
    # Regression: an empty message and a 32-byte zero message must not share signatures.
    secret = 3
    public_key = schnorr_public_key(secret)
    signature = schnorr_sign(b"", secret, bytes(32))
    assert schnorr_verify(b"", signature, public_key)
    assert not schnorr_verify(bytes(32), signature, public_key)


def test_bip340_rejects_non_bytes_messages() -> None:
    with pytest.raises(TypeError):
        schnorr_sign("text", 3, bytes(32))  # type: ignore[arg-type]
    assert not schnorr_verify("text", bytes(64), bytes(32))  # type: ignore[arg-type]


def test_advanced_suite_schnorr_trace_accepts_any_message_length() -> None:
    for message in ("", "short", "x" * 32, "a longer message that exceeds thirty-two bytes"):
        trace = advanced_suite.schnorr_bip340_sign_and_verify_trace(3, message)
        assert trace["verified"] is True
        signature = bytes.fromhex(trace["R_x_hex"][2:] + trace["sig_s_hex"][2:])
        assert schnorr.schnorr_verify(message.encode(), signature,
                                      bytes.fromhex(trace["x_only_pubkey_P_hex"][2:]))
    assert advanced_suite.bip340_message_arg("") == ""
