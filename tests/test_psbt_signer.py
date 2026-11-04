"""Tests for the BIP-174 PSBT Signer role (P2WPKH and P2SH-P2WPKH).

The primary oracle is the BIP-143 worked examples (``bip143_signing_vectors.json``):
a correct deterministic (RFC 6979, low-S) signer reproduces the example DER
signatures byte-for-byte. The secondary oracle is the existing
``bip143_sighash`` and ECDSA implementations.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from keylab import hd, mnemonic, psbt
from keylab.ec import secp256k1
from keylab.encoding.transaction import (
    Transaction,
    TxIn,
    TxOut,
    bip143_sighash,
    compact_size,
    parse_transaction,
    ser_string,
)
from keylab.psbt.model import (
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_WITNESS_UTXO,
    PSBT_MAGIC,
    KeyPair,
    Psbt,
)
from keylab.psbt.signer import PsbtSignError

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "bip143_signing_vectors.json").read_text(encoding="utf-8")
)["cases"]
CASES = {case["name"]: case for case in VECTORS}


# --- helpers ---------------------------------------------------------------

def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _record(key: bytes, value: bytes) -> bytes:
    return compact_size(len(key)) + key + compact_size(len(value)) + value


def _witness_utxo_value(amount: int, script_pubkey: bytes) -> bytes:
    return amount.to_bytes(8, "little") + ser_string(script_pubkey)


def _build_psbt_bytes(case: dict) -> bytes:
    """Assemble raw PSBT bytes around a BIP-143 signing example."""
    unsigned_tx = bytes.fromhex(case["unsigned_tx"])
    tx = parse_transaction(unsigned_tx)
    out = bytearray(PSBT_MAGIC)
    out += _record(bytes([PSBT_GLOBAL_UNSIGNED_TX]), unsigned_tx) + b"\x00"  # global map
    for index in range(len(tx.inputs)):
        if index == case["input_index"]:
            out += _record(bytes([PSBT_IN_WITNESS_UTXO]),
                           _witness_utxo_value(case["amount"], bytes.fromhex(case["scriptpubkey"])))
            if "redeem_script" in case:
                out += _record(bytes([PSBT_IN_REDEEM_SCRIPT]), bytes.fromhex(case["redeem_script"]))
        out += b"\x00"  # input map separator (empty map for non-signable inputs)
    for _ in range(len(tx.outputs)):
        out += b"\x00"  # empty output maps
    return bytes(out)


def _p2wpkh_psbt_for_pubkey(pubkey: bytes, amount: int = 100_000) -> bytes:
    """A minimal 1-in/1-out unsigned-tx PSBT whose single input is P2WPKH for ``pubkey``."""
    pkh = _hash160(pubkey)
    script_pubkey = b"\x00\x14" + pkh
    txin = TxIn(prev_txid=bytes(32), prev_index=0, script_sig=b"", sequence=0xFFFFFFFF)
    txout = TxOut(amount=amount - 1000, script_pubkey=b"\x00\x14" + bytes(20))
    tx = Transaction(version=2, inputs=(txin,), outputs=(txout,), locktime=0)
    unsigned_tx = (
        tx.version.to_bytes(4, "little")
        + compact_size(1) + txin.prev_txid + txin.prev_index.to_bytes(4, "little")
        + ser_string(txin.script_sig) + txin.sequence.to_bytes(4, "little")
        + compact_size(1) + txout.serialize()
        + tx.locktime.to_bytes(4, "little")
    )
    out = bytearray(PSBT_MAGIC)
    out += _record(bytes([PSBT_GLOBAL_UNSIGNED_TX]), unsigned_tx) + b"\x00"
    out += _record(bytes([PSBT_IN_WITNESS_UTXO]), _witness_utxo_value(amount, script_pubkey)) + b"\x00"
    out += b"\x00"  # one empty output map
    return bytes(out)


def _der_decode(sig: bytes) -> tuple[int, int]:
    assert sig[0] == 0x30
    r_len = sig[3]
    r = int.from_bytes(sig[4:4 + r_len], "big")
    s_off = 4 + r_len + 2
    s_len = sig[4 + r_len + 1]
    s = int.from_bytes(sig[s_off:s_off + s_len], "big")
    return r, s


def _partial_sig(signed: Psbt, index: int, pubkey: bytes) -> bytes | None:
    return signed.inputs[index].get(PSBT_IN_PARTIAL_SIG, pubkey)


# --- known-answer / vector tests ------------------------------------------

@pytest.mark.parametrize("name", list(CASES))
def test_sign_input_matches_bip143_known_answer(name):
    case = CASES[name]
    parsed = psbt.parse(_build_psbt_bytes(case))
    scalar = int(case["private_key"], 16)
    signed = psbt.sign_input(parsed, case["input_index"], scalar)
    sig = _partial_sig(signed, case["input_index"], bytes.fromhex(case["public_key"]))
    assert sig is not None
    assert sig.hex() == case["der_signature"]


@pytest.mark.parametrize("name", list(CASES))
def test_sighash_cross_check_against_bip143(name):
    case = CASES[name]
    tx = parse_transaction(bytes.fromhex(case["unsigned_tx"]))
    digest = bip143_sighash(tx, case["input_index"], bytes.fromhex(case["script_code"]),
                            case["amount"], case["sighash_type"])
    assert digest.hex() == case["sighash"]


@pytest.mark.parametrize("name", list(CASES))
def test_inserted_signature_verifies(name):
    case = CASES[name]
    parsed = psbt.parse(_build_psbt_bytes(case))
    scalar = int(case["private_key"], 16)
    signed = psbt.sign_input(parsed, case["input_index"], scalar)
    sig = _partial_sig(signed, case["input_index"], bytes.fromhex(case["public_key"]))
    r, s = _der_decode(sig[:-1])
    tx = parse_transaction(bytes.fromhex(case["unsigned_tx"]))
    digest = bip143_sighash(tx, case["input_index"], bytes.fromhex(case["script_code"]),
                            case["amount"], sig[-1])
    point = secp256k1.public_key_from_private_scalar(scalar)
    assert secp256k1.ecdsa_verify_digest(digest, (r, s), point)
    assert not secp256k1.is_high_s_signature((r, s))


@pytest.mark.parametrize("name", list(CASES))
def test_sign_multi_signs_matching_input_only(name):
    case = CASES[name]
    raw = _build_psbt_bytes(case)
    parsed = psbt.parse(raw)
    scalar = int(case["private_key"], 16)
    pubkey = bytes.fromhex(case["public_key"])
    assert psbt.signable_inputs(parsed, [scalar]) == [case["input_index"]]
    signed = psbt.sign(parsed, [scalar])
    assert _partial_sig(signed, case["input_index"], pubkey).hex() == case["der_signature"]
    # every other input is untouched
    for index, inp in enumerate(signed.inputs):
        if index != case["input_index"]:
            assert inp.pairs == parsed.inputs[index].pairs


# --- required validation behaviours ---------------------------------------

def test_deterministic_signature():
    case = CASES["bip143-native-p2wpkh"]
    parsed = psbt.parse(_build_psbt_bytes(case))
    scalar = int(case["private_key"], 16)
    a = psbt.sign_input(parsed, case["input_index"], scalar)
    b = psbt.sign_input(parsed, case["input_index"], scalar)
    assert psbt.serialize(a) == psbt.serialize(b)


def test_existing_partial_signatures_preserved():
    case = CASES["bip143-native-p2wpkh"]
    parsed = psbt.parse(_build_psbt_bytes(case))
    index = case["input_index"]
    # a pre-existing partial sig from some *other* signer's pubkey
    other_pubkey = b"\x02" + bytes(32)
    foreign = KeyPair(bytes([PSBT_IN_PARTIAL_SIG]) + other_pubkey, b"\xde\xad")
    parsed.inputs[index].pairs.insert(0, foreign)
    signed = psbt.sign_input(parsed, index, int(case["private_key"], 16))
    assert foreign in signed.inputs[index].pairs
    assert _partial_sig(signed, index, bytes.fromhex(case["public_key"])) is not None


def test_wrong_key_rejected():
    case = CASES["bip143-native-p2wpkh"]
    parsed = psbt.parse(_build_psbt_bytes(case))
    with pytest.raises(PsbtSignError, match="does not match"):
        psbt.sign_input(parsed, case["input_index"], 0x1234)


def test_missing_witness_utxo_rejected():
    case = CASES["bip143-native-p2wpkh"].copy()
    tx = parse_transaction(bytes.fromhex(case["unsigned_tx"]))
    raw = bytearray(PSBT_MAGIC)
    raw += _record(bytes([PSBT_GLOBAL_UNSIGNED_TX]), bytes.fromhex(case["unsigned_tx"])) + b"\x00"
    raw += b"\x00" * len(tx.inputs)  # all empty input maps: no witness UTXO
    raw += b"\x00" * len(tx.outputs)
    parsed = psbt.parse(bytes(raw))
    with pytest.raises(PsbtSignError, match="witness UTXO"):
        psbt.sign_input(parsed, case["input_index"], int(case["private_key"], 16))


def test_missing_redeem_script_rejected():
    case = CASES["bip143-p2sh-p2wpkh"]
    tx = parse_transaction(bytes.fromhex(case["unsigned_tx"]))
    raw = bytearray(PSBT_MAGIC)
    raw += _record(bytes([PSBT_GLOBAL_UNSIGNED_TX]), bytes.fromhex(case["unsigned_tx"])) + b"\x00"
    raw += _record(bytes([PSBT_IN_WITNESS_UTXO]),
                   _witness_utxo_value(case["amount"], bytes.fromhex(case["scriptpubkey"]))) + b"\x00"
    raw += b"\x00" * len(tx.outputs)
    parsed = psbt.parse(bytes(raw))
    with pytest.raises(PsbtSignError, match="redeem script"):
        psbt.sign_input(parsed, case["input_index"], int(case["private_key"], 16))


def test_invalid_index_rejected():
    case = CASES["bip143-native-p2wpkh"]
    parsed = psbt.parse(_build_psbt_bytes(case))
    with pytest.raises(PsbtSignError, match="out of range"):
        psbt.sign_input(parsed, 99, int(case["private_key"], 16))


@pytest.mark.parametrize("bad", [0, secp256k1.N, -1, b"\x00" * 31])
def test_invalid_private_key_rejected(bad):
    case = CASES["bip143-native-p2wpkh"]
    parsed = psbt.parse(_build_psbt_bytes(case))
    with pytest.raises(PsbtSignError):
        psbt.sign_input(parsed, case["input_index"], bad)


def test_duplicate_partial_signature_rejected():
    case = CASES["bip143-native-p2wpkh"]
    parsed = psbt.parse(_build_psbt_bytes(case))
    scalar = int(case["private_key"], 16)
    signed = psbt.sign_input(parsed, case["input_index"], scalar)
    with pytest.raises(PsbtSignError, match="already has a partial signature"):
        psbt.sign_input(signed, case["input_index"], scalar)


def test_sign_is_idempotent_and_skips_signed_inputs():
    case = CASES["bip143-native-p2wpkh"]
    parsed = psbt.parse(_build_psbt_bytes(case))
    scalar = int(case["private_key"], 16)
    once = psbt.sign(parsed, [scalar])
    twice = psbt.sign(once, [scalar])  # already signed -> no-op, no duplicate
    assert psbt.serialize(once) == psbt.serialize(twice)
    assert psbt.signable_inputs(once, [scalar]) == []


def test_unsupported_input_type_rejected():
    # a P2WSH scriptPubKey (0x0020 + 32) is out of scope
    script_pubkey = b"\x00\x20" + bytes(32)
    txin = TxIn(prev_txid=bytes(32), prev_index=0, script_sig=b"", sequence=0xFFFFFFFF)
    tx_bytes = (
        (2).to_bytes(4, "little") + compact_size(1) + txin.prev_txid
        + txin.prev_index.to_bytes(4, "little") + ser_string(b"") + txin.sequence.to_bytes(4, "little")
        + compact_size(0) + (0).to_bytes(4, "little")
    )
    raw = bytearray(PSBT_MAGIC)
    raw += _record(bytes([PSBT_GLOBAL_UNSIGNED_TX]), tx_bytes) + b"\x00"
    raw += _record(bytes([PSBT_IN_WITNESS_UTXO]), _witness_utxo_value(1000, script_pubkey)) + b"\x00"
    parsed = psbt.parse(bytes(raw))
    with pytest.raises(PsbtSignError, match="unsupported input type"):
        psbt.sign_input(parsed, 0, 0x1)
    # sign() silently skips it
    assert psbt.sign(parsed, [0x1]).inputs[0].pairs == parsed.inputs[0].pairs


def test_round_trip_serialize_sign_serialize():
    case = CASES["bip143-p2sh-p2wpkh"]
    raw = _build_psbt_bytes(case)
    parsed = psbt.parse(raw)
    signed = psbt.sign_input(parsed, case["input_index"], int(case["private_key"], 16))
    blob = psbt.serialize(signed)
    reparsed = psbt.parse(blob)  # re-validates
    assert psbt.serialize(reparsed) == blob
    assert reparsed.inputs[case["input_index"]].get(
        PSBT_IN_PARTIAL_SIG, bytes.fromhex(case["public_key"])
    ).hex() == case["der_signature"]
    # input bytes are a strict prefix-free extension: signing only grew the input map
    assert len(blob) > len(raw)


def test_input_psbt_not_mutated():
    case = CASES["bip143-native-p2wpkh"]
    parsed = psbt.parse(_build_psbt_bytes(case))
    before = psbt.serialize(parsed)
    psbt.sign_input(parsed, case["input_index"], int(case["private_key"], 16))
    assert psbt.serialize(parsed) == before


# --- BIP-39 / BIP-32 interaction ------------------------------------------

def test_sign_with_bip39_hd_derived_key():
    seed = mnemonic.mnemonic_to_seed(
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about"
    )
    priv, _chain = hd.derive_private_path(seed, "m/84'/0'/0'/0/0")
    scalar = int.from_bytes(priv, "big")
    pubkey = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(scalar))
    parsed = psbt.parse(_p2wpkh_psbt_for_pubkey(pubkey))
    signed = psbt.sign(parsed, [priv])  # pass the 32-byte key material directly
    sig = _partial_sig(signed, 0, pubkey)
    assert sig is not None
    r, s = _der_decode(sig[:-1])
    tx = parse_transaction(parsed.unsigned_tx_bytes)
    script_code = b"\x76\xa9\x14" + _hash160(pubkey) + b"\x88\xac"
    digest = bip143_sighash(tx, 0, script_code, 100_000, sig[-1])
    assert secp256k1.ecdsa_verify_digest(digest, (r, s), secp256k1.public_key_from_private_scalar(scalar))


# --- regression ------------------------------------------------------------

def test_regression_native_p2wpkh_signature_bytes():
    case = CASES["bip143-native-p2wpkh"]
    parsed = psbt.parse(_build_psbt_bytes(case))
    signed = psbt.sign_input(parsed, 1, int(case["private_key"], 16))
    sig = _partial_sig(signed, 1, bytes.fromhex(case["public_key"]))
    assert sig.hex() == (
        "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a"
        "0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01"
    )


# --- property-based --------------------------------------------------------

@settings(max_examples=40, deadline=None)
@given(scalar=st.integers(min_value=1, max_value=secp256k1.N - 1))
def test_property_sign_verifies_and_round_trips(scalar):
    pubkey = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(scalar))
    raw = _p2wpkh_psbt_for_pubkey(pubkey)
    parsed = psbt.parse(raw)
    signed = psbt.sign_input(parsed, 0, scalar)
    sig = _partial_sig(signed, 0, pubkey)
    assert sig is not None and sig[-1] == 0x01
    r, s = _der_decode(sig[:-1])
    assert not secp256k1.is_high_s_signature((r, s))
    tx = parse_transaction(parsed.unsigned_tx_bytes)
    script_code = b"\x76\xa9\x14" + _hash160(pubkey) + b"\x88\xac"
    digest = bip143_sighash(tx, 0, script_code, 100_000, 0x01)
    assert secp256k1.ecdsa_verify_digest(digest, (r, s), secp256k1.public_key_from_private_scalar(scalar))
    # output differs from input only by the one added record
    blob = psbt.serialize(signed)
    assert psbt.serialize(psbt.parse(blob)) == blob
    assert signed.inputs[0].pairs[:-1] == parsed.inputs[0].pairs


def test_benchmark_psbt_sign_correctness_gate():
    from keylab.benchmarks import benchmark_psbt_sign

    report = benchmark_psbt_sign(count=2)
    assert report["benchmark"] == "bip174-psbt-sign"
    assert report["outputs_match_vectors"] is True
    assert report["single_input_cases"] == 1
    assert report["multi_input_cases"] == 1


@settings(max_examples=30, deadline=None)
@given(scalar=st.integers(min_value=1, max_value=secp256k1.N - 1),
       other=st.integers(min_value=1, max_value=secp256k1.N - 1))
def test_property_wrong_key_never_signs(scalar, other):
    pubkey = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(scalar))
    other_pub = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(other))
    if _hash160(other_pub) == _hash160(pubkey):
        return  # same key: skip
    parsed = psbt.parse(_p2wpkh_psbt_for_pubkey(pubkey))
    with pytest.raises(PsbtSignError):
        psbt.sign_input(parsed, 0, other)
    assert psbt.signable_inputs(parsed, [other]) == []
