"""Tests for the BIP-174 PSBT Finalizer role (P2WPKH and P2SH-P2WPKH).

The primary oracle is the BIP-143 worked examples
(``bip143_signing_vectors.json``): a correct finalizer reproduces the example
final ``scriptSig`` and ``scriptWitness`` byte-for-byte. The secondary oracle is
the existing PSBT parser/validator, BIP-143 sighash, and PSBT signer.
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
    TxIn,
    TxOut,
    compact_size,
    parse_transaction,
    ser_string,
)
from keylab.psbt.finalizer import PsbtFinalizeError
from keylab.psbt.model import (
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_SIGHASH_TYPE,
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


def _signed(case: dict):
    parsed = psbt.parse(_build_psbt_bytes(case))
    return psbt.sign_input(parsed, case["input_index"], int(case["private_key"], 16))


def _p2wpkh_signed_psbt_for_scalar(scalar: int, amount: int = 100_000):
    pubkey = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(scalar))
    script_pubkey = b"\x00\x14" + _hash160(pubkey)
    txin = TxIn(prev_txid=bytes(32), prev_index=0, script_sig=b"", sequence=0xFFFFFFFF)
    txout = TxOut(amount=amount - 1000, script_pubkey=b"\x00\x14" + bytes(20))
    unsigned = (
        (2).to_bytes(4, "little") + compact_size(1) + txin.prev_txid + txin.prev_index.to_bytes(4, "little")
        + ser_string(b"") + txin.sequence.to_bytes(4, "little")
        + compact_size(1) + txout.serialize() + (0).to_bytes(4, "little")
    )
    out = bytearray(PSBT_MAGIC)
    out += _record(bytes([PSBT_GLOBAL_UNSIGNED_TX]), unsigned) + b"\x00"
    out += _record(bytes([PSBT_IN_WITNESS_UTXO]), _witness_utxo_value(amount, script_pubkey)) + b"\x00"
    out += b"\x00"
    return psbt.sign_input(psbt.parse(bytes(out)), 0, scalar)


# --- known-answer / vector tests ------------------------------------------

@pytest.mark.parametrize("name", list(CASES))
def test_finalize_matches_bip143_scriptsig_and_witness(name):
    case = CASES[name]
    final = psbt.finalize_input(_signed(case), case["input_index"])
    inp = final.inputs[case["input_index"]]
    sig = inp.get(PSBT_IN_FINAL_SCRIPTSIG)
    assert (sig.hex() if sig is not None else "") == case["final_scriptsig"]
    assert inp.get(PSBT_IN_FINAL_SCRIPTWITNESS).hex() == case["final_scriptwitness"]


@pytest.mark.parametrize("name", list(CASES))
def test_finalize_removes_redundant_signing_fields(name):
    case = CASES[name]
    final = psbt.finalize_input(_signed(case), case["input_index"])
    types = set(final.inputs[case["input_index"]].types())
    # redundant signing fields gone
    assert PSBT_IN_PARTIAL_SIG not in types
    assert PSBT_IN_SIGHASH_TYPE not in types
    assert PSBT_IN_REDEEM_SCRIPT not in types
    # witness UTXO retained, finals present
    assert PSBT_IN_WITNESS_UTXO in types
    assert PSBT_IN_FINAL_SCRIPTWITNESS in types


def test_finalize_single_input_is_finalized():
    case = CASES["bip143-p2sh-p2wpkh"]
    final = psbt.finalize(_signed(case))
    assert psbt.is_finalized(final)


def test_finalize_valid_p2wpkh():
    case = CASES["bip143-native-p2wpkh"]
    final = psbt.finalize_input(_signed(case), case["input_index"])
    assert final.inputs[case["input_index"]].get(PSBT_IN_FINAL_SCRIPTSIG) is None  # native: no scriptSig
    assert final.inputs[case["input_index"]].get(PSBT_IN_FINAL_SCRIPTWITNESS) is not None


def test_finalize_valid_p2sh_p2wpkh():
    case = CASES["bip143-p2sh-p2wpkh"]
    final = psbt.finalize_input(_signed(case), case["input_index"])
    assert final.inputs[case["input_index"]].get(PSBT_IN_FINAL_SCRIPTSIG) is not None


# --- required negative behaviours -----------------------------------------

def test_missing_partial_signature_rejected():
    case = CASES["bip143-native-p2wpkh"]
    parsed = psbt.parse(_build_psbt_bytes(case))  # not signed
    with pytest.raises(PsbtFinalizeError, match="no partial signature"):
        psbt.finalize_input(parsed, case["input_index"])


def test_incorrect_signature_rejected():
    case = CASES["bip143-native-p2wpkh"]
    signed = _signed(case)
    index = case["input_index"]
    pubkey = bytes.fromhex(case["public_key"])
    # corrupt the DER signature body (flip a byte in r), keep structure/sighash
    good = signed.inputs[index].get(PSBT_IN_PARTIAL_SIG, pubkey)
    bad = bytearray(good)
    bad[5] ^= 0x01
    signed.inputs[index].pairs = [
        KeyPair(bytes([PSBT_IN_PARTIAL_SIG]) + pubkey, bytes(bad))
        if p.key_type == PSBT_IN_PARTIAL_SIG else p
        for p in signed.inputs[index].pairs
    ]
    with pytest.raises(PsbtFinalizeError, match="does not verify"):
        psbt.finalize_input(signed, index)


def test_wrong_public_key_rejected():
    case = CASES["bip143-native-p2wpkh"]
    signed = _signed(case)
    index = case["input_index"]
    # replace the partial sig's key with an unrelated (valid) pubkey
    other = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(0x123456))
    value = next(p.value for p in signed.inputs[index].pairs if p.key_type == PSBT_IN_PARTIAL_SIG)
    signed.inputs[index].pairs = [
        KeyPair(bytes([PSBT_IN_PARTIAL_SIG]) + other, value)
        if p.key_type == PSBT_IN_PARTIAL_SIG else p
        for p in signed.inputs[index].pairs
    ]
    with pytest.raises(PsbtFinalizeError, match="no partial signature matches"):
        psbt.finalize_input(signed, index)


def test_missing_witness_utxo_rejected():
    case = CASES["bip143-native-p2wpkh"]
    tx = parse_transaction(bytes.fromhex(case["unsigned_tx"]))
    # a PSBT carrying a partial sig but no witness UTXO
    raw = bytearray(PSBT_MAGIC)
    raw += _record(bytes([PSBT_GLOBAL_UNSIGNED_TX]), bytes.fromhex(case["unsigned_tx"])) + b"\x00"
    for index in range(len(tx.inputs)):
        if index == case["input_index"]:
            raw += _record(bytes([PSBT_IN_PARTIAL_SIG]) + bytes.fromhex(case["public_key"]),
                           bytes.fromhex(case["der_signature"]))
        raw += b"\x00"
    raw += b"\x00" * len(tx.outputs)
    parsed = psbt.parse(bytes(raw))
    with pytest.raises(PsbtFinalizeError, match="witness UTXO"):
        psbt.finalize_input(parsed, case["input_index"])


def test_missing_redeem_script_rejected():
    case = CASES["bip143-p2sh-p2wpkh"]
    tx = parse_transaction(bytes.fromhex(case["unsigned_tx"]))
    raw = bytearray(PSBT_MAGIC)
    raw += _record(bytes([PSBT_GLOBAL_UNSIGNED_TX]), bytes.fromhex(case["unsigned_tx"])) + b"\x00"
    raw += _record(bytes([PSBT_IN_WITNESS_UTXO]),
                   _witness_utxo_value(case["amount"], bytes.fromhex(case["scriptpubkey"])))
    raw += _record(bytes([PSBT_IN_PARTIAL_SIG]) + bytes.fromhex(case["public_key"]),
                   bytes.fromhex(case["der_signature"])) + b"\x00"
    raw += b"\x00" * len(tx.outputs)
    parsed = psbt.parse(bytes(raw))
    with pytest.raises(PsbtFinalizeError, match="redeem script"):
        psbt.finalize_input(parsed, case["input_index"])


def test_already_finalized_rejected():
    case = CASES["bip143-p2sh-p2wpkh"]
    final = psbt.finalize_input(_signed(case), case["input_index"])
    with pytest.raises(PsbtFinalizeError, match="already finalized"):
        psbt.finalize_input(final, case["input_index"])


def test_duplicate_finalization_is_noop_in_bulk():
    case = CASES["bip143-p2sh-p2wpkh"]
    once = psbt.finalize(_signed(case))
    twice = psbt.finalize(once)  # already finalized -> skipped, no change
    assert psbt.serialize(once) == psbt.serialize(twice)


def test_invalid_index_rejected():
    case = CASES["bip143-native-p2wpkh"]
    with pytest.raises(PsbtFinalizeError, match="out of range"):
        psbt.finalize_input(_signed(case), 99)


# --- round-trip and non-mutation ------------------------------------------

def test_round_trip_serialize_finalize_serialize():
    case = CASES["bip143-p2sh-p2wpkh"]
    final = psbt.finalize_input(_signed(case), case["input_index"])
    blob = psbt.serialize(final)
    reparsed = psbt.parse(blob)  # re-validates
    assert psbt.serialize(reparsed) == blob
    assert reparsed.inputs[case["input_index"]].get(PSBT_IN_FINAL_SCRIPTWITNESS).hex() == case["final_scriptwitness"]


def test_finalize_does_not_mutate_input_or_tx():
    case = CASES["bip143-p2sh-p2wpkh"]
    signed = _signed(case)
    before = psbt.serialize(signed)
    unsigned_before = signed.unsigned_tx_bytes
    psbt.finalize_input(signed, case["input_index"])
    assert psbt.serialize(signed) == before  # input PSBT unchanged
    # the unsigned transaction is never altered by finalization
    final = psbt.finalize_input(signed, case["input_index"])
    assert final.unsigned_tx_bytes == unsigned_before


def test_finalize_preserves_unknown_and_other_inputs():
    case = CASES["bip143-native-p2wpkh"]  # 2-input tx; input 0 unsupported/unsigned
    signed = _signed(case)
    index = case["input_index"]
    # attach an unknown-type record (type 0x09, a valid 1-byte varint) that must survive
    unknown = KeyPair(bytes([0x09]) + b"xx", b"\x01\x02")
    signed.inputs[index].pairs.append(unknown)
    other_before = signed.inputs[0].pairs[:]
    final = psbt.finalize_input(signed, index)
    assert unknown in final.inputs[index].pairs           # unknown preserved
    assert final.inputs[0].pairs == other_before           # other input untouched


# --- benchmark correctness gate -------------------------------------------

def test_benchmark_psbt_finalize_correctness_gate():
    from keylab.benchmarks import benchmark_psbt_finalize

    report = benchmark_psbt_finalize(count=2)
    assert report["benchmark"] == "bip174-psbt-finalize"
    assert report["outputs_match_vectors"] is True
    assert report["single_input_cases"] == 1
    assert report["multi_input_cases"] == 1


# --- regression ------------------------------------------------------------

def test_regression_p2sh_p2wpkh_final_bytes():
    case = CASES["bip143-p2sh-p2wpkh"]
    final = psbt.finalize_input(_signed(case), case["input_index"])
    inp = final.inputs[case["input_index"]]
    assert inp.get(PSBT_IN_FINAL_SCRIPTSIG).hex() == "16001479091972186c449eb1ded22b78e40d009bdf0089"
    assert inp.get(PSBT_IN_FINAL_SCRIPTWITNESS).hex() == (
        "02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f"
        "0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01"
        "2103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873"
    )


# --- property-based --------------------------------------------------------

@settings(max_examples=40, deadline=None)
@given(scalar=st.integers(min_value=1, max_value=secp256k1.N - 1))
def test_property_finalize_round_trips_and_consumes_only_signatures(scalar):
    signed = _p2wpkh_signed_psbt_for_scalar(scalar)
    unsigned_before = signed.unsigned_tx_bytes
    final = psbt.finalize_input(signed, 0)
    # the finalized witness is the signed partial sig + pubkey; no new signature created
    inp = final.inputs[0]
    assert PSBT_IN_PARTIAL_SIG not in inp.types()
    assert inp.get(PSBT_IN_FINAL_SCRIPTWITNESS) is not None
    # transaction untouched; result round-trips and re-validates
    assert final.unsigned_tx_bytes == unsigned_before
    blob = psbt.serialize(final)
    assert psbt.serialize(psbt.parse(blob)) == blob
    assert psbt.is_finalized(final)


@settings(max_examples=30, deadline=None)
@given(scalar=st.integers(min_value=1, max_value=secp256k1.N - 1))
def test_property_unsigned_input_never_finalizes(scalar):
    pubkey = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(scalar))
    script_pubkey = b"\x00\x14" + _hash160(pubkey)
    unsigned = (
        (2).to_bytes(4, "little") + compact_size(1) + bytes(32) + (0).to_bytes(4, "little")
        + ser_string(b"") + (0xFFFFFFFF).to_bytes(4, "little")
        + compact_size(0) + (0).to_bytes(4, "little")
    )
    out = bytearray(PSBT_MAGIC)
    out += _record(bytes([PSBT_GLOBAL_UNSIGNED_TX]), unsigned) + b"\x00"
    out += _record(bytes([PSBT_IN_WITNESS_UTXO]), _witness_utxo_value(1000, script_pubkey)) + b"\x00"
    parsed = psbt.parse(bytes(out))
    with pytest.raises(PsbtFinalizeError):
        psbt.finalize_input(parsed, 0)
    assert psbt.serialize(psbt.finalize(parsed)) == psbt.serialize(parsed)  # no-op
