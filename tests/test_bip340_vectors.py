"""Official BIP-340 test vectors 0-18, including variable-length messages."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from keylab import advanced_suite
from keylab.ec import schnorr
from keylab.ec.schnorr import schnorr_public_key, schnorr_sign, schnorr_verify

with (Path(__file__).parent / "vectors" / "bip340_test_vectors.csv").open(encoding="utf-8") as _csv:
    VECTORS = list(csv.DictReader(_csv))


def test_fixture_contains_all_nineteen_official_vectors() -> None:
    assert [int(row["index"]) for row in VECTORS] == list(range(19))


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
