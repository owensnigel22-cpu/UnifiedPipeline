"""Official BIP-173 (Bech32) and BIP-350 (Bech32m) test vectors."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from keylab.encoding import bech32

VECTORS = json.loads((Path(__file__).parent / "vectors" / "bech32_vectors.json").read_text(encoding="utf-8"))
BIP173, BIP350 = VECTORS["bip173"], VECTORS["bip350"]
NETWORK_HRPS = {"bc", "tb"}


def _decode_address(address: str) -> bytes:
    """Decode a mainnet/testnet SegWit address to its scriptPubKey, as a wallet would."""
    hrp, version, program = bech32.decode_segwit_address(address)
    if hrp not in NETWORK_HRPS:
        raise ValueError("unexpected human-readable part")
    return bytes([version + 0x50 if version else 0, len(program)]) + program


def test_fixture_counts_match_the_bips() -> None:
    assert [len(BIP173[k]) for k in ("valid_checksum", "invalid_checksum", "valid_address", "invalid_address")] == [7, 12, 6, 10]
    assert [len(BIP350[k]) for k in ("valid_checksum", "invalid_checksum", "valid_address", "invalid_address")] == [7, 14, 8, 15]


@pytest.mark.parametrize("text", BIP173["valid_checksum"])
def test_bip173_valid_bech32_checksums(text: str) -> None:
    assert bech32.decode(text)[2] == bech32.BECH32


@pytest.mark.parametrize("text", BIP350["valid_checksum"])
def test_bip350_valid_bech32m_checksums(text: str) -> None:
    assert bech32.decode(text)[2] == bech32.BECH32M


@pytest.mark.parametrize("case", BIP173["invalid_checksum"] + BIP350["invalid_checksum"],
                         ids=lambda c: c["reason"])
def test_invalid_checksum_strings_are_rejected(case: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        bech32.decode(case["string"])


def test_bech32_and_bech32m_valid_strings_are_mutually_exclusive() -> None:
    # BIP-350: "No string can be simultaneously valid Bech32 and Bech32m".
    assert all(bech32.decode(s)[2] == bech32.BECH32 for s in BIP173["valid_checksum"])
    assert all(bech32.decode(s)[2] == bech32.BECH32M for s in BIP350["valid_checksum"])


@pytest.mark.parametrize("case", BIP350["valid_address"], ids=lambda c: c["string"][:16])
def test_bip350_valid_addresses_decode_to_script_pubkey(case: dict[str, str]) -> None:
    assert _decode_address(case["string"]).hex() == case["script_pubkey"]


@pytest.mark.parametrize("case", BIP173["valid_address"], ids=lambda c: c["string"][:16])
def test_bip173_addresses_follow_bip350_rules(case: dict[str, str]) -> None:
    witness_version = int(case["script_pubkey"][:2], 16)
    if witness_version == 0:
        assert _decode_address(case["string"]).hex() == case["script_pubkey"]
        return
    # BIP-350 superseded BIP-173 for witness v1+: those must now use Bech32m, so the
    # original Bech32 strings are rejected while their checksums still decode as Bech32.
    assert bech32.decode(case["string"])[2] == bech32.BECH32
    with pytest.raises(ValueError, match="checksum variant"):
        _decode_address(case["string"])
    hrp, data, _ = bech32.decode(case["string"])
    reencoded = bech32.encode(hrp, data, bech32.BECH32M)
    assert _decode_address(reencoded).hex() == case["script_pubkey"]


@pytest.mark.parametrize("case", BIP173["invalid_address"] + BIP350["invalid_address"],
                         ids=lambda c: c["reason"])
def test_invalid_addresses_are_rejected(case: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        _decode_address(case["string"])


@pytest.mark.parametrize("case", BIP350["valid_address"], ids=lambda c: c["string"][:16])
def test_valid_addresses_round_trip_through_the_encoder(case: dict[str, str]) -> None:
    hrp, version, program = bech32.decode_segwit_address(case["string"])
    assert bech32.encode_segwit_address(hrp, version, program) == case["string"].lower()
