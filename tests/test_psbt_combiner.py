"""Tests for the BIP-174 PSBT Combiner role.

Primary oracle: the official BIP-174 Combiner worked example
(``bip174_combiner_vectors.json``) -- combining the two signer PSBTs yields the
expected combined PSBT (as a key/value set per map; BIP-174 v0 does not mandate
record order). Secondary oracle: the existing parser/validator and the
signer/finalizer/extractor (cross-role combine -> finalize -> extract).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from keylab import psbt
from keylab.ec import secp256k1
from keylab.encoding.transaction import compact_size, parse_transaction, ser_string
from keylab.psbt.combiner import PsbtCombineError
from keylab.psbt.model import (
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_WITNESS_UTXO,
    PSBT_MAGIC,
    KeyPair,
    Psbt,
)
from keylab.psbt.signer import _hash160

VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "bip174_combiner_vectors.json").read_text(encoding="utf-8")
)["combine"]
SIGNING = {
    c["name"]: c for c in json.loads(
        (Path(__file__).parent / "vectors" / "bip143_signing_vectors.json").read_text(encoding="utf-8")
    )["cases"]
}


# --- helpers ---------------------------------------------------------------

def _kv(psbt_obj: Psbt):
    """A map-by-map (key, value)-set view, order-independent."""
    def s(m):
        return frozenset((kp.key, kp.value) for kp in m.pairs)
    return (s(psbt_obj.global_map),
            tuple(s(m) for m in psbt_obj.inputs),
            tuple(s(m) for m in psbt_obj.outputs))


def _record(key: bytes, value: bytes) -> bytes:
    return compact_size(len(key)) + key + compact_size(len(value)) + value


def _witness_utxo_value(amount: int, script_pubkey: bytes) -> bytes:
    return amount.to_bytes(8, "little") + ser_string(script_pubkey)


def _p2wpkh_base_bytes(pubkey: bytes, amount: int = 100_000, *, with_witness_utxo: bool = True) -> bytes:
    script_pubkey = b"\x00\x14" + _hash160(pubkey)
    unsigned = (
        (2).to_bytes(4, "little") + compact_size(1) + bytes(32) + (0).to_bytes(4, "little")
        + ser_string(b"") + (0xFFFFFFFF).to_bytes(4, "little")
        + compact_size(1) + (amount - 1000).to_bytes(8, "little") + ser_string(b"\x00\x14" + bytes(20))
        + (0).to_bytes(4, "little")
    )
    out = bytearray(PSBT_MAGIC)
    out += _record(bytes([PSBT_GLOBAL_UNSIGNED_TX]), unsigned) + b"\x00"
    if with_witness_utxo:
        out += _record(bytes([PSBT_IN_WITNESS_UTXO]), _witness_utxo_value(amount, script_pubkey))
    out += b"\x00"
    out += b"\x00"
    return bytes(out)


# --- official BIP-174 vector ----------------------------------------------

@pytest.mark.parametrize("case", VECTORS, ids=lambda c: c["name"])
def test_official_combiner_vector(case):
    a = psbt.parse(bytes.fromhex(case["input1"]))
    b = psbt.parse(bytes.fromhex(case["input2"]))
    expected = psbt.parse(bytes.fromhex(case["expected"]))
    combined = psbt.combine([a, b])
    assert _kv(combined) == _kv(expected)
    assert len(psbt.serialize(combined)) == len(bytes.fromhex(case["expected"]))


@pytest.mark.parametrize("case", VECTORS, ids=lambda c: c["name"])
def test_official_combiner_vector_order_independent(case):
    a = psbt.parse(bytes.fromhex(case["input1"]))
    b = psbt.parse(bytes.fromhex(case["input2"]))
    assert _kv(psbt.combine([a, b])) == _kv(psbt.combine([b, a]))


@pytest.mark.parametrize("case", VECTORS, ids=lambda c: c["name"])
def test_combine_round_trips(case):
    a = psbt.parse(bytes.fromhex(case["input1"]))
    b = psbt.parse(bytes.fromhex(case["input2"]))
    blob = psbt.serialize(psbt.combine([a, b]))
    assert psbt.serialize(psbt.parse(blob)) == blob  # re-validates


# --- union semantics -------------------------------------------------------

def test_union_of_two_distinct_partial_sigs():
    scalar_a = 0x1111
    pub_a = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(scalar_a))
    base = psbt.parse(_p2wpkh_base_bytes(pub_a))
    # two PSBTs over the same unsigned tx, each carrying a different partial sig
    a = psbt.parse(psbt.serialize(base))
    a.inputs[0].pairs.append(KeyPair(bytes([PSBT_IN_PARTIAL_SIG]) + pub_a, b"\x30\x06sigAAA\x01"))
    pub_b = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(0x2222))
    b = psbt.parse(psbt.serialize(base))
    b.inputs[0].pairs.append(KeyPair(bytes([PSBT_IN_PARTIAL_SIG]) + pub_b, b"\x30\x06sigBBB\x01"))
    combined = psbt.combine([a, b])
    assert combined.inputs[0].get(PSBT_IN_PARTIAL_SIG, pub_a) == b"\x30\x06sigAAA\x01"
    assert combined.inputs[0].get(PSBT_IN_PARTIAL_SIG, pub_b) == b"\x30\x06sigBBB\x01"


def test_identical_records_deduplicated():
    pub = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(0x3333))
    a = psbt.parse(_p2wpkh_base_bytes(pub))
    combined = psbt.combine([a, psbt.parse(psbt.serialize(a))])
    assert _kv(combined) == _kv(a)
    # no duplicated witness-utxo record
    assert sum(1 for p in combined.inputs[0].pairs if p.key_type == PSBT_IN_WITNESS_UTXO) == 1


def test_first_value_precedence_on_benign_conflict():
    pub = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(0x4444))
    a = psbt.parse(_p2wpkh_base_bytes(pub))
    b = psbt.parse(_p2wpkh_base_bytes(pub))
    # same unknown key, different value -> first-value wins (benign, non-critical type)
    a.inputs[0].pairs.append(KeyPair(bytes([0x09]) + b"k", b"AAA"))
    b.inputs[0].pairs.append(KeyPair(bytes([0x09]) + b"k", b"BBB"))
    combined = psbt.combine([a, b])
    assert combined.inputs[0].get(0x09, b"k") == b"AAA"
    combined_rev = psbt.combine([b, a])
    assert combined_rev.inputs[0].get(0x09, b"k") == b"BBB"


def test_single_psbt_combine_is_identity():
    pub = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(0x5555))
    a = psbt.parse(_p2wpkh_base_bytes(pub))
    assert _kv(psbt.combine([a])) == _kv(a)


def test_unknown_keys_preserved():
    pub = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(0x6666))
    a = psbt.parse(_p2wpkh_base_bytes(pub))
    b = psbt.parse(_p2wpkh_base_bytes(pub))
    a.global_map.pairs.append(KeyPair(bytes([0xFC]) + b"propA", b"\x01"))
    b.inputs[0].pairs.append(KeyPair(bytes([0x7F]) + b"unk", b"\x02\x03"))
    combined = psbt.combine([a, b])
    assert combined.global_map.get(0xFC, b"propA") == b"\x01"
    assert combined.inputs[0].get(0x7F, b"unk") == b"\x02\x03"


# --- negative --------------------------------------------------------------

def test_empty_input_rejected():
    with pytest.raises(PsbtCombineError, match="at least one"):
        psbt.combine([])


def test_differing_unsigned_tx_rejected():
    a = psbt.parse(_p2wpkh_base_bytes(secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(0x7777))))
    b = psbt.parse(_p2wpkh_base_bytes(secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(0x8888)), amount=200_000))
    with pytest.raises(PsbtCombineError, match="same unsigned transaction"):
        psbt.combine([a, b])


def test_conflicting_finalized_field_rejected_strict():
    pub = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(0x9999))
    a = psbt.parse(_p2wpkh_base_bytes(pub))
    b = psbt.parse(_p2wpkh_base_bytes(pub))
    a.inputs[0].pairs.append(KeyPair(bytes([PSBT_IN_FINAL_SCRIPTWITNESS]), b"\x01\x01A"))
    b.inputs[0].pairs.append(KeyPair(bytes([PSBT_IN_FINAL_SCRIPTWITNESS]), b"\x01\x01B"))
    with pytest.raises(PsbtCombineError, match="finalized field"):
        psbt.combine([a, b])
    # non-strict downgrades to first-value
    combined = psbt.combine([a, b], strict=False)
    assert combined.inputs[0].get(PSBT_IN_FINAL_SCRIPTWITNESS) == b"\x01\x01A"


def test_non_bytes_member_rejected():
    with pytest.raises((PsbtCombineError, AttributeError, TypeError)):
        psbt.combine([object()])  # type: ignore[list-item]


# --- cross-role: combine -> finalize -> extract ---------------------------

def test_combine_then_finalize_then_extract_matches_bip143():
    case = SIGNING["bip143-p2sh-p2wpkh"]
    tx = bytes.fromhex(case["unsigned_tx"])
    from keylab.psbt.model import PSBT_IN_REDEEM_SCRIPT
    base = bytearray(PSBT_MAGIC)
    base += _record(bytes([PSBT_GLOBAL_UNSIGNED_TX]), tx) + b"\x00"
    base += _record(bytes([PSBT_IN_WITNESS_UTXO]), _witness_utxo_value(case["amount"], bytes.fromhex(case["scriptpubkey"])))
    base += _record(bytes([PSBT_IN_REDEEM_SCRIPT]), bytes.fromhex(case["redeem_script"])) + b"\x00"
    base += b"\x00" * len(parse_transaction(tx).outputs)
    parsed = psbt.parse(bytes(base))
    signed = psbt.sign_input(parsed, case["input_index"], int(case["private_key"], 16))
    # combine an empty copy with the signed one; the partial sig must survive
    empty = psbt.parse(bytes(base))
    combined = psbt.combine([empty, signed])
    final = psbt.finalize_input(combined, case["input_index"])
    assert psbt.extract(final).hex() == case["final_tx"]


# --- benchmark correctness gate -------------------------------------------

def test_benchmark_psbt_combine_correctness_gate():
    from keylab.benchmarks import benchmark_psbt_combine

    report = benchmark_psbt_combine(count=2)
    assert report["benchmark"] == "bip174-psbt-combine"
    assert report["outputs_match_vectors"] is True
    assert report["cases"] >= 1


# --- regression ------------------------------------------------------------

def test_regression_official_combined_length_and_kv():
    case = VECTORS[0]
    combined = psbt.combine([psbt.parse(bytes.fromhex(case["input1"])),
                             psbt.parse(bytes.fromhex(case["input2"]))])
    assert len(psbt.serialize(combined)) == 1332
    assert _kv(combined) == _kv(psbt.parse(bytes.fromhex(case["expected"])))


# --- property-based --------------------------------------------------------

@settings(max_examples=40, deadline=None)
@given(scalar=st.integers(min_value=1, max_value=secp256k1.N - 1),
       va=st.binary(min_size=1, max_size=8), vb=st.binary(min_size=1, max_size=8))
def test_property_union_is_exact_and_commutative(scalar, va, vb):
    pub = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(scalar))
    a = psbt.parse(_p2wpkh_base_bytes(pub))
    b = psbt.parse(_p2wpkh_base_bytes(pub))
    a.inputs[0].pairs.append(KeyPair(bytes([0x09]) + b"a", va))  # disjoint unknown keys
    b.inputs[0].pairs.append(KeyPair(bytes([0x09]) + b"b", vb))
    combined = psbt.combine([a, b])
    assert combined.inputs[0].get(0x09, b"a") == va
    assert combined.inputs[0].get(0x09, b"b") == vb
    assert _kv(combined) == _kv(psbt.combine([b, a]))  # commutative on disjoint keys
    blob = psbt.serialize(combined)
    assert psbt.serialize(psbt.parse(blob)) == blob


@settings(max_examples=30, deadline=None)
@given(scalar=st.integers(min_value=1, max_value=secp256k1.N - 1))
def test_property_combine_idempotent(scalar):
    pub = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(scalar))
    a = psbt.parse(_p2wpkh_base_bytes(pub))
    assert _kv(psbt.combine([a, a])) == _kv(a)
