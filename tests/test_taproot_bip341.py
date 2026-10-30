"""Official BIP-341 wallet test vectors: script trees, key-path sighash and signing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from keylab.ec.schnorr import schnorr_public_key, schnorr_verify
from keylab.encoding.taproot import (
    TapLeaf,
    build_script_tree,
    taproot_output,
    taproot_script_tree_output,
    taproot_sign_key_path,
    taproot_tweak_seckey,
    verify_taproot_script_path,
)
from keylab.encoding.transaction import (
    TxOut,
    compact_size,
    parse_transaction,
    taproot_precomputed_hashes,
    taproot_sighash,
    taproot_signature_message,
)

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "bip341_wallet_test_vectors.json").read_text(encoding="utf-8")
)
KEY_PATH = VECTORS["keyPathSpending"][0]
TX = parse_transaction(bytes.fromhex(KEY_PATH["given"]["rawUnsignedTx"]))
UTXOS = [TxOut(u["amountSats"], bytes.fromhex(u["scriptPubKey"])) for u in KEY_PATH["given"]["utxosSpent"]]


def _tree(node: object) -> object:
    if node is None:
        return None
    if isinstance(node, dict):
        return TapLeaf(bytes.fromhex(node["script"]), node["leafVersion"])
    assert isinstance(node, list) and len(node) == 2
    return [_tree(node[0]), _tree(node[1])]


@pytest.mark.parametrize("index", range(len(VECTORS["scriptPubKey"])))
def test_bip341_script_pubkey_vectors(index: int) -> None:
    case = VECTORS["scriptPubKey"][index]
    given, intermediary, expected = case["given"], case["intermediary"], case["expected"]
    internal = bytes.fromhex(given["internalPubkey"])
    tree = _tree(given["scriptTree"])
    output, controls = taproot_script_tree_output(internal, tree)  # type: ignore[arg-type]

    assert output.tweak.to_bytes(32, "big").hex() == intermediary["tweak"]
    assert output.output_key_x.hex() == intermediary["tweakedPubkey"]
    assert "5120" + output.output_key_x.hex() == expected["scriptPubKey"]
    assert output.address == expected["bip350Address"]
    if tree is None:
        assert intermediary["merkleRoot"] is None and controls == ()
        return
    built = build_script_tree(tree)  # type: ignore[arg-type]
    assert built.merkle_root.hex() == intermediary["merkleRoot"]
    assert [leaf.leaf_hash.hex() for leaf in built.leaves] == intermediary["leafHashes"]
    assert [control.hex() for control in controls] == expected["scriptPathControlBlocks"]
    for leaf, control in zip(built.leaves, controls):
        assert verify_taproot_script_path(output.output_key_x, leaf.leaf.script, control)


def test_bip341_precomputed_transaction_hashes() -> None:
    hashes = taproot_precomputed_hashes(TX, UTXOS)
    for name, value in KEY_PATH["intermediary"].items():
        assert hashes[name].hex() == value


@pytest.mark.parametrize("case", KEY_PATH["inputSpending"],
                         ids=lambda c: f"input{c['given']['txinIndex']}-type{c['given']['hashType']}")
def test_bip341_key_path_spending_vectors(case: dict[str, dict[str, object]]) -> None:
    given, intermediary, expected = case["given"], case["intermediary"], case["expected"]
    index, hash_type = given["txinIndex"], given["hashType"]
    private = int(given["internalPrivkey"], 16)  # type: ignore[arg-type]
    root = bytes.fromhex(given["merkleRoot"]) if given["merkleRoot"] else b""  # type: ignore[arg-type]

    assert schnorr_public_key(private).hex() == intermediary["internalPubkey"]
    assert taproot_output(bytes.fromhex(intermediary["internalPubkey"]), root).tweak == int(
        intermediary["tweak"], 16)  # type: ignore[arg-type]
    assert f"{taproot_tweak_seckey(private, root):064x}" == intermediary["tweakedPrivkey"]
    message = taproot_signature_message(TX, index, UTXOS, hash_type)  # type: ignore[arg-type]
    assert message.hex() == intermediary["sigMsg"]
    sighash = taproot_sighash(TX, index, UTXOS, hash_type)  # type: ignore[arg-type]
    assert sighash.hex() == intermediary["sigHash"]
    # The published witnesses were produced with an all-zero aux_rand.
    witness = taproot_sign_key_path(sighash, private, root, hash_type=hash_type, aux_rand=bytes(32))  # type: ignore[arg-type]
    assert [witness.hex()] == expected["witness"]
    output_key = taproot_output(schnorr_public_key(private), root).output_key_x
    assert schnorr_verify(sighash, witness[:64], output_key)


def test_parse_transaction_round_trips_witness_and_legacy_fields() -> None:
    signed = parse_transaction(bytes.fromhex(VECTORS["keyPathSpending"][0]["auxiliary"]["fullySignedTx"]))
    assert signed.version == TX.version and signed.locktime == TX.locktime
    assert [txin.outpoint for txin in signed.inputs] == [txin.outpoint for txin in TX.inputs]
    assert signed.outputs == TX.outputs
    assert any(txin.witness for txin in signed.inputs)
    assert all(not txin.witness for txin in TX.inputs)


def test_sighash_rejects_invalid_parameters() -> None:
    with pytest.raises(ValueError, match="hash type"):
        taproot_sighash(TX, 0, UTXOS, 0x04)
    with pytest.raises(ValueError, match="input index"):
        taproot_sighash(TX, len(TX.inputs), UTXOS)
    with pytest.raises(ValueError, match="spent output"):
        taproot_sighash(TX, 0, UTXOS[:-1])
    with pytest.raises(ValueError, match="annex"):
        taproot_sighash(TX, 0, UTXOS, annex=b"\x51")
    with pytest.raises(ValueError, match="SIGHASH_SINGLE"):
        taproot_sighash(TX, len(TX.outputs), UTXOS, 0x03)


def test_annex_and_script_path_extensions_change_the_message() -> None:
    import hashlib

    base = taproot_signature_message(TX, 0, UTXOS)
    annex = b"\x50\x01"
    with_annex = taproot_signature_message(TX, 0, UTXOS, annex=annex)
    # spend_type gains the annex bit and sha_annex is appended after input_index.
    assert with_annex == (base[:-5] + b"\x01" + base[-4:]
                          + hashlib.sha256(compact_size(len(annex)) + annex).digest())
    leaf = TapLeaf(b"\x51").leaf_hash
    script_path = taproot_signature_message(TX, 0, UTXOS, leaf_hash=leaf)
    # ext_flag = 1 sets spend_type to 2, then tapleaf_hash || key_version || codesep_pos.
    assert script_path == base[:-5] + b"\x02" + base[-4:] + leaf + b"\x00" + b"\xff\xff\xff\xff"


def test_key_path_signature_length_tracks_hash_type() -> None:
    sighash = bytes(range(32))
    assert len(taproot_sign_key_path(sighash, 7, aux_rand=bytes(32))) == 64
    assert taproot_sign_key_path(sighash, 7, hash_type=0x83, aux_rand=bytes(32))[-1] == 0x83
    with pytest.raises(ValueError, match="hash type"):
        taproot_sign_key_path(sighash, 7, hash_type=0x84)


def test_tweaked_secret_matches_tweaked_public_key_for_both_parities() -> None:
    root = bytes(range(32))
    for private in (1, 2, 3, 0xC0FFEE):
        tweaked = taproot_tweak_seckey(private, root)
        assert schnorr_public_key(tweaked) == taproot_output(schnorr_public_key(private), root).output_key_x


def test_script_tree_builder_rejects_malformed_nodes() -> None:
    with pytest.raises(ValueError):
        build_script_tree([TapLeaf(b"\x51")])  # type: ignore[list-item]
    with pytest.raises(ValueError):
        build_script_tree(b"\x51")  # type: ignore[arg-type]


@pytest.mark.parametrize("value,encoded", [(0, "00"), (252, "fc"), (253, "fdfd00"),
                                           (0x10000, "fe00000100"), (1 << 32, "ff0000000001000000")])
def test_compact_size_encoding(value: int, encoded: str) -> None:
    assert compact_size(value).hex() == encoded
