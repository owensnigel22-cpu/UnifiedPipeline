"""Forward public-key/address checks, including the supplied public example pair."""

import hashlib
import secrets

import pytest

from keylab.cli import main
from keylab.ec.secp256k1 import N, compress_pubkey, scalar_mult
from keylab.encoding.address import address_to_target_hash, hash160, p2pkh_address, p2wpkh_address
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