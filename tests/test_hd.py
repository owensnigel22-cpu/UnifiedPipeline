import hashlib

import pytest

from keylab.hd import (
    derive_bip44_accounts,
    derive_bip44_p2pkh,
    derive_bip86_p2tr,
    mnemonic_to_seed,
    parse_path,
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

