"""Forward public-key/address checks, including the supplied public example pair."""

import hashlib
import secrets

import pytest

from keylab.cli import main
from keylab.ec.secp256k1 import N, compress_pubkey, scalar_mult
from keylab.encoding.address import (
    address_belongs_to_wif,
    address_to_target_hash,
    derive_addresses_from_wif,
    hash160,
    p2pkh_address,
    p2sh_p2wpkh_address,
    p2tr_address,
    p2wpkh_address,
    verify_pubkey_from_address,
)
from keylab.encoding.wif import decode, encode

KNOWN_WIF = "KwHV8WDsBUuXPymuan5TQN82tPyRWZ68vb14ww8p9FFCw6a17xkR"
KNOWN_P2WPKH = "bc1q956d8j8ypxvk3aewnyrxx4u0dqyxf6a7exsprn"


def test_supplied_wif_to_p2wpkh_forward_vector() -> None:
    key, compressed, network = decode(KNOWN_WIF)
    assert compressed and network == "mainnet"
    public_key = compress_pubkey(scalar_mult(int.from_bytes(key, "big")))
    assert p2wpkh_address(public_key) == KNOWN_P2WPKH
    assert len(address_to_target_hash(KNOWN_P2WPKH)) == 20


def test_p2pkh_forward_and_target_hash_round_trip() -> None:
    public_key = compress_pubkey(scalar_mult(1))
    address = p2pkh_address(public_key)
    assert len(address_to_target_hash(address)) == 20


def test_known_scalar_one_generates_known_p2pkh_and_p2wpkh_addresses() -> None:
    public_key = compress_pubkey(scalar_mult(1))
    expected_hash160 = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    p2pkh = p2pkh_address(public_key)
    p2wpkh = p2wpkh_address(public_key)

    assert p2pkh == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    assert p2wpkh == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert address_to_target_hash(p2pkh) == expected_hash160
    assert address_to_target_hash(p2wpkh) == expected_hash160


def test_known_address_backwards_to_public_key_and_test_scalar() -> None:
    address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    target_hash = address_to_target_hash(address)
    public_key = compress_pubkey(scalar_mult(1))
    sha256_digest = hashlib.sha256(public_key).digest()

    assert target_hash.hex() == "751e76e8199196d454941c45d1b3a323f1433bd6"
    assert sha256_digest.hex() == "0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554"
    assert hash160(public_key) == target_hash
    assert p2pkh_address(public_key) == address


def test_generated_ephemeral_key_runs_full_forward_address_pipeline() -> None:
    private_key = secrets.randbelow(N - 1) + 1
    wif = encode(private_key, compressed=True)
    decoded_key, compressed, network = decode(wif)
    public_key = compress_pubkey(scalar_mult(int.from_bytes(decoded_key, "big")))
    sha256_digest = hashlib.sha256(public_key).digest()
    expected_hash160 = hash160(public_key)
    address = p2wpkh_address(public_key, network)

    assert compressed and network == "mainnet"
    assert decoded_key == private_key.to_bytes(32, "big")
    assert len(sha256_digest) == 32
    assert len(expected_hash160) == 20
    assert address_to_target_hash(address) == expected_hash160


def test_address_hash_cli_prints_hash160(capsys) -> None:
    assert main(["address-hash", KNOWN_P2WPKH]) == 0
    assert capsys.readouterr().out.strip() == "2d34d3c8e4099968f72e990663578f680864ebbe"


def test_address_hash_cli_rejects_invalid_address() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["address-hash", "not-a-bitcoin-address"])
    assert exc_info.value.code == 2


def test_p2wpkh_testnet_round_trip() -> None:
    public_key = compress_pubkey(scalar_mult(2))
    address = p2wpkh_address(public_key, "testnet")
    assert len(address_to_target_hash(address)) == 20


def test_candidate_public_key_verification_covers_common_address_types() -> None:
    public_key = compress_pubkey(scalar_mult(7))
    addresses = (
        p2pkh_address(public_key),
        p2sh_p2wpkh_address(public_key),
        p2wpkh_address(public_key),
        p2tr_address(public_key[1:]),
    )
    assert all(verify_pubkey_from_address(address, public_key) for address in addresses)
    assert not verify_pubkey_from_address(p2pkh_address(compress_pubkey(scalar_mult(8))), public_key)


def test_wif_public_derivation_returns_all_address_families_without_private_scalar() -> None:
    result = derive_addresses_from_wif(encode(1, compressed=True))
    assert result["p2pkh"] == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    assert str(result["p2sh_p2wpkh"]).startswith("3")
    assert str(result["p2wpkh"]).startswith("bc1q")
    assert str(result["p2tr"]).startswith("bc1p")
    assert "private_scalar" not in result
    assert "private_key_hex" not in result
    revealed = derive_addresses_from_wif(encode(1, compressed=True), reveal_private=True)
    assert revealed["private_key_hex"] == f"{1:064x}"


def test_canonical_compressed_wif_derives_all_expected_address_families() -> None:
    wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    result = derive_addresses_from_wif(wif)
    assert result["p2pkh"] == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    assert result["p2sh_p2wpkh"] == "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"
    assert result["p2wpkh"] == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"


@pytest.mark.parametrize(
    ("address_type", "target"),
    [
        ("p2pkh", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
        ("p2sh_p2wpkh", "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"),
        ("p2wpkh", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
    ],
)
def test_address_belongs_to_wif_identifies_exact_address_type(address_type: str, target: str) -> None:
    wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    result = address_belongs_to_wif(wif, target)
    assert result["verified"] is True
    assert result["matches"] == [address_type]
    assert "wif" not in result
    assert "private_key_hex" not in result


def test_address_belongs_to_wif_rejects_wrong_address_and_accepts_uppercase_bech32() -> None:
    wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    target = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    assert address_belongs_to_wif(wif, target.upper())["matches"] == ["p2wpkh"]
    other = address_belongs_to_wif(wif, "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")
    assert other["verified"] is False
    assert other["matches"] == []


def test_wif_derive_cli_echoes_wif_only_when_requested(capsys) -> None:
    from keylab.cli import main

    wif = encode(1, compressed=True)
    assert main(["wif-derive", "--wif", wif]) == 0
    default_output = capsys.readouterr().out
    assert wif not in default_output
    assert "private_key_hex" not in default_output
    assert main(["wif-derive", "--wif", wif, "--show-wif"]) == 0
    opted_in_output = capsys.readouterr().out
    assert wif in opted_in_output
    assert "private_key_hex" not in opted_in_output
