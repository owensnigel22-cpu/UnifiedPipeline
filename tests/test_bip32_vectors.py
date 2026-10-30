"""Official BIP-32 test vectors 1-5 and BIP-49/84/86 derivation vectors."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from keylab.encoding.wif import decode as decode_wif
from keylab.hd import (
    HARDENED,
    ExtendedKey,
    derive_account_key,
    derive_bip44_p2pkh,
    derive_bip49_p2sh_p2wpkh,
    derive_bip84_p2wpkh,
    derive_bip86_p2tr,
    derive_child_private,
    derive_child_public,
    derive_private_path,
    fingerprint,
    format_path,
    key_identifier,
    mnemonic_to_seed,
    parse_path,
)

VECTOR_DIR = Path(__file__).parent / "vectors"
BIP32 = json.loads((VECTOR_DIR / "bip32_test_vectors.json").read_text(encoding="utf-8"))
DERIVATION = json.loads((VECTOR_DIR / "bip_derivation_vectors.json").read_text(encoding="utf-8"))
CHAINS = [(vector["vector"], vector["seed"], chain)
          for vector in BIP32["valid"] for chain in vector["chains"]]
SEED = mnemonic_to_seed(DERIVATION["bip86"]["mnemonic"])


def test_fixture_covers_vectors_one_to_five() -> None:
    assert [vector["vector"] for vector in BIP32["valid"]] == [1, 2, 3, 4]
    assert len(CHAINS) == 17
    assert len(BIP32["invalid"]) == 16


@pytest.mark.parametrize("number,seed,chain", CHAINS, ids=lambda v: str(v))
def test_bip32_full_path_derivation_matches_official_vector(number: int, seed: str,
                                                           chain: dict[str, str]) -> None:
    node = ExtendedKey.from_seed(bytes.fromhex(seed)).derive(chain["path"])
    assert node.serialize() == chain["xprv"]
    assert node.neuter().serialize() == chain["xpub"]
    # The tuple-based API must agree with the extended-key object.
    key, chain_code = derive_private_path(bytes.fromhex(seed), chain["path"])
    assert (key, chain_code) == (node.key, node.chain_code)


@pytest.mark.parametrize("number,seed,chain", CHAINS, ids=lambda v: str(v))
def test_bip32_serialization_round_trips(number: int, seed: str, chain: dict[str, str]) -> None:
    for text in (chain["xprv"], chain["xpub"]):
        assert ExtendedKey.parse(text).serialize() == text
    assert ExtendedKey.parse(chain["xprv"]).neuter() == ExtendedKey.parse(chain["xpub"])


@pytest.mark.parametrize("case", BIP32["invalid"], ids=lambda c: c["reason"])
def test_bip32_vector_five_rejects_invalid_extended_keys(case: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        ExtendedKey.parse(case["key"])


def test_ckdpub_matches_ckdpriv_for_every_non_hardened_official_step() -> None:
    checked = 0
    for _, seed, chain in CHAINS:
        indices = parse_path(chain["path"])
        if not indices or indices[-1] & HARDENED:
            continue
        parent = ExtendedKey.from_seed(bytes.fromhex(seed)).derive(format_path(indices[:-1]))
        assert parent.neuter().child(indices[-1]).serialize() == chain["xpub"]
        child_pub, child_chain = derive_child_public(parent.public_key, parent.chain_code, indices[-1])
        assert (child_pub, child_chain) == (ExtendedKey.parse(chain["xpub"]).key,
                                            ExtendedKey.parse(chain["xpub"]).chain_code)
        checked += 1
    assert checked >= 5


def test_public_derivation_cannot_cross_hardened_edges() -> None:
    xpub = ExtendedKey.parse(BIP32["valid"][0]["chains"][0]["xpub"])
    with pytest.raises(ValueError, match="hardened"):
        xpub.child(HARDENED)
    with pytest.raises(ValueError, match="hardened"):
        derive_child_public(xpub.key, xpub.chain_code, HARDENED | 5)


def test_fingerprint_and_parent_identifier_link_parent_to_child() -> None:
    root = ExtendedKey.from_seed(bytes.fromhex(BIP32["valid"][0]["seed"]))
    # BIP-32 test vector 1 master identifier, published in the BIP's examples.
    assert root.fingerprint.hex() == "3442193e"
    assert fingerprint(root.public_key) == root.fingerprint
    assert key_identifier(root.public_key) == root.identifier
    child = root.child(HARDENED)
    assert child.parent_fingerprint == root.fingerprint
    assert child.depth == 1 and child.child_number == HARDENED


def test_format_path_inverts_parse_path() -> None:
    for path in ("m", "m/0'", "m/0/2147483647'/1/2147483646'/2", "m/44'/0'/0'/0/5"):
        assert format_path(parse_path(path)) == path


def test_legacy_tuple_api_still_matches_extended_key_child() -> None:
    root = ExtendedKey.from_seed(bytes.fromhex(BIP32["valid"][1]["seed"]))
    for index in (0, 1, HARDENED, HARDENED + 7):
        assert derive_child_private(root.key, root.chain_code, index) == (
            root.child(index).key, root.child(index).chain_code)


def test_bip86_vectors() -> None:
    vectors = DERIVATION["bip86"]
    root = ExtendedKey.from_seed(SEED)
    assert root.serialize() == vectors["rootpriv"]
    assert root.neuter().serialize() == vectors["rootpub"]
    assert derive_account_key(SEED, 86).serialize() == vectors["entries"][0]["xprv"]
    for entry in vectors["entries"]:
        node = root.derive(entry["path"])
        assert node.serialize() == entry["xprv"]
        assert node.neuter().serialize() == entry["xpub"]
        if "address" in entry:
            _, _, _, _, change, index = entry["path"].split("/")
            derived = derive_bip86_p2tr(SEED, 0, int(index), change=int(change))
            assert derived.address == entry["address"]
            assert derived.internal_key_x.hex() == entry["internal_key"]
            assert derived.output_key_x.hex() == entry["output_key"]
            assert entry["scriptPubKey"] == "5120" + entry["output_key"]


def test_bip84_vectors() -> None:
    vectors = DERIVATION["bip84"]
    root = ExtendedKey.from_seed(SEED, family="z")
    assert root.serialize() == vectors["rootpriv"]
    assert root.neuter().serialize() == vectors["rootpub"]
    account = derive_account_key(SEED, 84)
    assert account.serialize() == vectors["entries"][0]["xpriv"]
    assert account.neuter().serialize() == vectors["entries"][0]["xpub"]
    for entry in vectors["entries"][1:]:
        _, _, _, _, change, index = entry["path"].split("/")
        derived = derive_bip84_p2wpkh(SEED, 0, int(index), change=int(change))
        assert derived.path == entry["path"]
        assert derived.address == entry["address"]
        assert derived.public_key.hex() == entry["pubkey"]
        key_bytes, compressed, network = decode_wif(entry["privkey"])
        assert compressed and network == "mainnet"
        assert key_bytes == root.derive(entry["path"]).key


def test_bip49_vectors() -> None:
    vectors = DERIVATION["bip49"]
    assert ExtendedKey.from_seed(SEED, family="u").serialize() == vectors["masterseed"]
    account = derive_account_key(SEED, 49, network="testnet")
    assert account.serialize() == vectors["account0Xpriv"]
    assert account.neuter().serialize() == vectors["account0Xpub"]
    derived = derive_bip49_p2sh_p2wpkh(SEED, 0, 0, network="testnet")
    assert derived.path == vectors["receive_path"]
    assert derived.public_key.hex() == vectors["account0recvPublicKeyHex"]
    assert derived.hash160.hex() == vectors["keyhash"]
    assert derived.address == vectors["address"]
    assert ExtendedKey.from_seed(SEED).derive(vectors["receive_path"]).key.hex() == (
        vectors["account0recvPrivateKeyHex"])


def test_change_chain_parameter_is_validated_and_backward_compatible() -> None:
    assert derive_bip44_p2pkh(SEED, 0, 0).path == "m/44'/0'/0'/0/0"
    assert derive_bip44_p2pkh(SEED, 0, 0, change=1).path == "m/44'/0'/0'/1/0"
    with pytest.raises(ValueError, match="change"):
        derive_bip84_p2wpkh(SEED, 0, 0, change=2)


def test_extended_key_rejects_inconsistent_construction() -> None:
    root = ExtendedKey.from_seed(SEED)
    with pytest.raises(ValueError, match="depth-0"):
        ExtendedKey(root.key, root.chain_code, True, 0, b"\x01\x02\x03\x04")
    with pytest.raises(ValueError, match="family"):
        root.with_family("q")
