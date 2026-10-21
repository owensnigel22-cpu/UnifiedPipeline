import hashlib

import pytest

from keylab.ec.secp256k1 import compress_pubkey, scalar_mult
from keylab.encoding.base58 import check_decode
from keylab.hd import (
    derive_bip44_accounts,
    derive_bip44_p2pkh,
    derive_bip86_p2tr,
    mnemonic_to_seed,
    parse_path,
    recover_unhardened_parent_private_key,
)

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def test_bip39_seed_matches_published_vector() -> None:
    assert mnemonic_to_seed(MNEMONIC).hex() == (
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19"
        "a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    )


def test_bip39_nfkd_normalizes_passphrase() -> None:
    assert mnemonic_to_seed(MNEMONIC, "é") == mnemonic_to_seed(MNEMONIC, "e\u0301")


def test_parse_path_and_reject_malformed_components() -> None:
    assert parse_path("m/44'/0'/1'/0/5") == (0x8000002C, 0x80000000, 0x80000001, 0, 5)
    with pytest.raises(ValueError):
        parse_path("m/44//0")


def test_bip44_derivation_is_repeatable_and_matches_attachment_digest() -> None:
    seed = mnemonic_to_seed(MNEMONIC)
    first = derive_bip44_p2pkh(seed, 0, 0)
    assert first == derive_bip44_p2pkh(seed, 0, 0)
    assert first.path == "m/44'/0'/0'/0/0"
    # The provided attachment reports this full digest for account 0, address 0.
    assert first.hash160.hex() == "d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa"
    assert hashlib.new("ripemd160", hashlib.sha256(first.public_key).digest()).digest() == first.hash160


def test_batched_account_derivation_matches_independent_paths() -> None:
    seed = mnemonic_to_seed(MNEMONIC)
    batch = derive_bip44_accounts(seed, 2, 2)
    assert len(batch) == 4
    assert [(item.account, item.address_index) for item in batch] == [
        (0, 0), (0, 1), (1, 0), (1, 1)
    ]
    assert all(item == derive_bip44_p2pkh(seed, item.account, item.address_index) for item in batch)


def test_bip86_derives_key_path_only_taproot_address() -> None:
    result = derive_bip86_p2tr(mnemonic_to_seed(MNEMONIC), 0, 0)
    assert result.path == "m/86'/0'/0'/0/0"
    assert result.address == "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"


def test_bip32_unhardened_parent_recovery_against_official_vector() -> None:
    # BIP-0032 test vector 1: the xprv values for m/0' and m/0'/1.
    parent_xprv = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    child_xprv = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
    parent_payload = check_decode(parent_xprv)
    child_payload = check_decode(child_xprv)
    assert len(parent_payload) == len(child_payload) == 78
    assert parent_payload[45] == child_payload[45] == 0
    parent_private = parent_payload[46:78]
    child_private = child_payload[46:78]
    parent_public = compress_pubkey(scalar_mult(int.from_bytes(parent_private, "big")))

    recovered = recover_unhardened_parent_private_key(
        child_private, parent_payload[13:45], parent_public, 1
    )
    assert recovered == parent_private


def test_bip32_parent_recovery_rejects_hardened_index() -> None:
    with pytest.raises(ValueError, match="non-hardened"):
        recover_unhardened_parent_private_key(b"\x01" * 32, b"\x02" * 32, b"", 0x80000000)

