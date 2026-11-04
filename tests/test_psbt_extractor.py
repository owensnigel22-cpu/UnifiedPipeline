"""Tests for the BIP-174 PSBT Extractor role (P2WPKH and P2SH-P2WPKH).

The primary oracle is the BIP-143 worked-example final signed transactions
(``bip143_signing_vectors.json`` ``final_tx``): sign -> finalize -> extract
reproduces them byte-for-byte. The secondary oracle is the existing
``parse_transaction`` (via the new ``serialize_transaction`` round-trip) and the
PSBT signer/finalizer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from keylab import psbt
from keylab.ec import secp256k1
from keylab.encoding.transaction import (
    compact_size,
    parse_transaction,
    ser_string,
    serialize_transaction,
)
from keylab.psbt.extractor import PsbtExtractError
from keylab.psbt.model import (
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_WITNESS_UTXO,
    PSBT_MAGIC,
    KeyPair,
)
from keylab.psbt.signer import _hash160

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "bip143_signing_vectors.json").read_text(encoding="utf-8")
)["cases"]
CASES = {case["name"]: case for case in VECTORS}


# --- helpers ---------------------------------------------------------------

def _record(key: bytes, value: bytes) -> bytes:
    return compact_size(len(key)) + key + compact_size(len(value)) + value


def _witness_utxo_value(amount: int, script_pubkey: bytes) -> bytes:
    return amount.to_bytes(8, "little") + ser_string(script_pubkey)


def _build_psbt_bytes(case: dict) -> bytes:
    unsigned_tx = bytes.fromhex(case["unsigned_tx"])
    tx = parse_transaction(unsigned_tx)
    out = bytearray(PSBT_MAGIC)
    out += _record(bytes([PSBT_GLOBAL_UNSIGNED_TX]), unsigned_tx) + b"\x00"
    for index in range(len(tx.inputs)):
        if index == case["input_index"]:
            out += _record(bytes([PSBT_IN_WITNESS_UTXO]),
                           _witness_utxo_value(case["amount"], bytes.fromhex(case["scriptpubkey"])))
            if "redeem_script" in case:
                out += _record(bytes([PSBT_IN_REDEEM_SCRIPT]), bytes.fromhex(case["redeem_script"]))
        out += b"\x00"
    for _ in range(len(tx.outputs)):
        out += b"\x00"
    return bytes(out)


def _sign_and_finalize(case: dict):
    parsed = psbt.parse(_build_psbt_bytes(case))
    signed = psbt.sign_input(parsed, case["input_index"], int(case["private_key"], 16))
    return psbt.finalize_input(signed, case["input_index"])


def _p2wpkh_finalized_psbt_for_scalar(scalar: int, amount: int = 100_000):
    pubkey = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(scalar))
    script_pubkey = b"\x00\x14" + _hash160(pubkey)
    unsigned = (
        (2).to_bytes(4, "little") + compact_size(1) + bytes(32) + (0).to_bytes(4, "little")
        + ser_string(b"") + (0xFFFFFFFF).to_bytes(4, "little")
        + compact_size(1) + (amount - 1000).to_bytes(8, "little") + ser_string(b"\x00\x14" + bytes(20))
        + (0).to_bytes(4, "little")
    )
    out = bytearray(PSBT_MAGIC)
    out += _record(bytes([PSBT_GLOBAL_UNSIGNED_TX]), unsigned) + b"\x00"
    out += _record(bytes([PSBT_IN_WITNESS_UTXO]), _witness_utxo_value(amount, script_pubkey)) + b"\x00"
    out += b"\x00"
    signed = psbt.sign_input(psbt.parse(bytes(out)), 0, scalar)
    return psbt.finalize_input(signed, 0)


# --- known-answer / vector tests ------------------------------------------

def test_extract_finalized_p2sh_p2wpkh_matches_bip143_final_tx():
    case = CASES["bip143-p2sh-p2wpkh"]
    final = _sign_and_finalize(case)
    assert psbt.is_finalized(final)
    assert psbt.extract(final).hex() == case["final_tx"]


def test_extract_finalized_p2wpkh_matches_bip143_final_tx():
    # Native example is a 2-input tx; input 0 is P2PK (out of scope). We finalize
    # input 1 (ours) and inject input 0's externally-finalized scriptSig taken
    # from the official final tx, then extract the full transaction.
    case = CASES["bip143-native-p2wpkh"]
    final_tx = case["final_tx"]
    input0_scriptsig = parse_transaction(bytes.fromhex(final_tx)).inputs[0].script_sig
    final = _sign_and_finalize(case)
    final.inputs[0].pairs.append(KeyPair(bytes([PSBT_IN_FINAL_SCRIPTSIG]), input0_scriptsig))
    assert psbt.is_finalized(final)
    assert psbt.extract(final).hex() == final_tx


def test_extract_transaction_preserves_unsigned_skeleton():
    case = CASES["bip143-p2sh-p2wpkh"]
    final = _sign_and_finalize(case)
    unsigned = parse_transaction(final.unsigned_tx_bytes)
    extracted = psbt.extract_transaction(final)
    assert extracted.version == unsigned.version
    assert extracted.locktime == unsigned.locktime
    assert extracted.outputs == unsigned.outputs
    for e, u in zip(extracted.inputs, unsigned.inputs, strict=True):
        assert e.prev_txid == u.prev_txid and e.prev_index == u.prev_index
        assert e.sequence == u.sequence  # only scriptSig/witness changed


# --- transaction serializer (BIP-144) round-trips -------------------------

@pytest.mark.parametrize("name", list(CASES))
def test_serialize_transaction_round_trips_final_tx(name):
    raw = bytes.fromhex(CASES[name]["final_tx"])
    assert serialize_transaction(parse_transaction(raw)) == raw


def test_serialize_transaction_round_trips_legacy():
    # the P2WPKH example's unsigned form is a legacy (no-witness) transaction
    raw = bytes.fromhex(CASES["bip143-native-p2wpkh"]["unsigned_tx"])
    out = serialize_transaction(parse_transaction(raw))
    assert out == raw
    assert out[4:6] != b"\x00\x01"  # no SegWit marker for a witnessless tx


def test_witness_serialization_correctness():
    case = CASES["bip143-p2sh-p2wpkh"]
    final = _sign_and_finalize(case)
    blob = psbt.extract(final)
    assert blob[4:6] == b"\x00\x01"  # SegWit marker/flag present
    tx = parse_transaction(blob)
    # the single input's witness is exactly <sig> <pubkey>
    assert len(tx.inputs[0].witness) == 2
    assert tx.inputs[0].witness[1].hex() == case["public_key"]


# --- required negative behaviours -----------------------------------------

def test_missing_final_scripts_rejected():
    case = CASES["bip143-p2sh-p2wpkh"]
    parsed = psbt.parse(_build_psbt_bytes(case))  # signed? no -- not even finalized
    with pytest.raises(PsbtExtractError, match="not finalized"):
        psbt.extract(parsed)


def test_partially_finalized_rejected():
    # 2-input native example: finalize only input 1, leave input 0 unfinalized
    case = CASES["bip143-native-p2wpkh"]
    final = _sign_and_finalize(case)  # only input 1 finalized
    assert not psbt.is_finalized(final)
    with pytest.raises(PsbtExtractError, match="input 0 is not finalized"):
        psbt.extract(final)


def test_invalid_finalized_witness_rejected():
    case = CASES["bip143-p2sh-p2wpkh"]
    final = _sign_and_finalize(case)
    index = case["input_index"]
    # corrupt the final scriptWitness: claim 3 items but provide a truncated stack
    final.inputs[index].pairs = [
        KeyPair(bytes([PSBT_IN_FINAL_SCRIPTWITNESS]), b"\x03\x01\xaa") if p.key_type == PSBT_IN_FINAL_SCRIPTWITNESS else p
        for p in final.inputs[index].pairs
    ]
    with pytest.raises(PsbtExtractError, match="scriptWitness"):
        psbt.extract(final)


def test_extract_does_not_mutate_input():
    case = CASES["bip143-p2sh-p2wpkh"]
    final = _sign_and_finalize(case)
    before = psbt.serialize(final)
    psbt.extract(final)
    assert psbt.serialize(final) == before


# --- boundary cases --------------------------------------------------------

def test_extract_witness_only_native_p2wpkh_single_input():
    # a single-input native P2WPKH PSBT: extracted tx is SegWit, input has empty scriptSig
    final = _p2wpkh_finalized_psbt_for_scalar(0xC0FFEE)
    blob = psbt.extract(final)
    tx = parse_transaction(blob)
    assert tx.inputs[0].script_sig == b""       # native: empty scriptSig
    assert len(tx.inputs[0].witness) == 2
    assert serialize_transaction(tx) == blob     # round-trips


# --- benchmark correctness gate -------------------------------------------

def test_benchmark_psbt_extract_correctness_gate():
    from keylab.benchmarks import benchmark_psbt_extract

    report = benchmark_psbt_extract(count=2)
    assert report["benchmark"] == "bip174-psbt-extract"
    assert report["outputs_match_vectors"] is True
    assert report["single_input_cases"] == 1
    assert report["multi_input_cases"] == 1


# --- regression ------------------------------------------------------------

def test_regression_p2sh_p2wpkh_final_tx_bytes():
    case = CASES["bip143-p2sh-p2wpkh"]
    final = _sign_and_finalize(case)
    assert psbt.extract(final).hex() == (
        "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477"
        "010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b0000"
        "00001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f00000000"
        "1976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3"
        "ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d"
        "877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c0066"
        "2ad1470198ac48c43f7d6f93a2a2687392040000"
    )


# --- property-based --------------------------------------------------------

@settings(max_examples=40, deadline=None)
@given(scalar=st.integers(min_value=1, max_value=secp256k1.N - 1))
def test_property_extract_round_trips_and_preserves_tx(scalar):
    final = _p2wpkh_finalized_psbt_for_scalar(scalar)
    unsigned_before = final.unsigned_tx_bytes
    blob = psbt.extract(final)
    # extraction is the inverse of parse, and never touches the unsigned skeleton
    assert serialize_transaction(parse_transaction(blob)) == blob
    assert final.unsigned_tx_bytes == unsigned_before
    extracted = parse_transaction(blob)
    unsigned = parse_transaction(unsigned_before)
    assert extracted.version == unsigned.version and extracted.locktime == unsigned.locktime
    assert extracted.outputs == unsigned.outputs
    assert all(e.prev_txid == u.prev_txid and e.sequence == u.sequence
               for e, u in zip(extracted.inputs, unsigned.inputs, strict=True))


@settings(max_examples=30, deadline=None)
@given(data=st.binary(min_size=0, max_size=8))
def test_property_malformed_witness_never_extracts(data):
    final = _p2wpkh_finalized_psbt_for_scalar(0xABCDEF)
    # replace the valid final witness with arbitrary bytes claiming many items
    bad = b"\xfd\xff\xff" + data  # compact_size says 65535 items; stack is short
    final.inputs[0].pairs = [
        KeyPair(bytes([PSBT_IN_FINAL_SCRIPTWITNESS]), bad) if p.key_type == PSBT_IN_FINAL_SCRIPTWITNESS else p
        for p in final.inputs[0].pairs
    ]
    with pytest.raises(PsbtExtractError):
        psbt.extract(final)
