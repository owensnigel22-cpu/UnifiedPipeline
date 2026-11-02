"""BIP-143 witness-v0 signature hash (M4.1), against the official vectors.

The worked examples in bip-0143.mediawiki are the oracle: for every case the
implementation must reproduce the published hashPrevouts/hashSequence/hashOutputs,
the full preimage, and the final sighash. Fixture provenance is pinned in
tests/vectors/SOURCES.json and checked by test_vector_provenance.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from keylab.encoding import transaction as tx_mod
from keylab.encoding.transaction import (
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    TxIn,
    TxOut,
    bip143_precomputed_hashes,
    bip143_sighash,
    bip143_signature_message,
    compact_size,
    parse_transaction,
    ser_string,
)

FAST = settings(max_examples=50, deadline=None)

_VEC = Path(__file__).parent / "vectors" / "bip143_sighash_vectors.json"
CASES = json.loads(_VEC.read_text(encoding="utf-8"))["cases"]
CASE_IDS = [c["name"] for c in CASES]


def _case(case: dict) -> tuple:
    tx = parse_transaction(bytes.fromhex(case["unsigned_tx"]))
    return tx, case["input_index"], bytes.fromhex(case["script_code"]), case["amount"], case["hash_type"]


# --- official vectors ---------------------------------------------------------------------------

@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_official_vector_intermediates_preimage_and_sighash(case: dict) -> None:
    tx, index, script_code, amount, hash_type = _case(case)
    hashes = bip143_precomputed_hashes(tx, index, hash_type)
    assert hashes["hashPrevouts"].hex() == case["hashPrevouts"]
    assert hashes["hashSequence"].hex() == case["hashSequence"]
    assert hashes["hashOutputs"].hex() == case["hashOutputs"]
    assert bip143_signature_message(tx, index, script_code, amount, hash_type).hex() == case["preimage"]
    assert bip143_sighash(tx, index, script_code, amount, hash_type).hex() == case["sighash"]


def test_every_defined_sighash_type_is_exercised() -> None:
    seen = {c["hash_type"] for c in CASES}
    assert {0x01, 0x02, 0x03, 0x81, 0x82, 0x83} <= seen


def test_vectors_cover_each_script_type() -> None:
    assert {c["tx_type"] for c in CASES} >= {"P2WPKH", "P2SH-P2WPKH", "P2WSH", "P2SH-P2WSH"}


def test_single_with_no_corresponding_output_commits_to_zero_hashoutputs() -> None:
    # The two native-P2WSH SINGLE cases sign input 1 of a 1-output tx (out of range).
    for case in CASES:
        if case["tx_type"] == "P2WSH" and case["hash_type"] == SIGHASH_SINGLE:
            tx, index, *_ = _case(case)
            assert index >= len(tx.outputs)
            assert bip143_precomputed_hashes(tx, index, SIGHASH_SINGLE)["hashOutputs"] == b"\x00" * 32


def test_regression_native_p2wpkh_sighash_constant() -> None:
    # Pin the canonical BIP-143 P2WPKH example sighash so a refactor cannot drift silently.
    case = next(c for c in CASES if c["name"] == "native-p2wpkh-all")
    tx, index, script_code, amount, hash_type = _case(case)
    assert bip143_sighash(tx, index, script_code, amount, hash_type).hex() == (
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    )


# --- parser round-trip --------------------------------------------------------------------------

def _reserialize_legacy(tx: tx_mod.Transaction) -> bytes:
    """Re-serialize a parsed non-witness transaction (the BIP-143 unsigned txs are legacy-form)."""
    out = tx.version.to_bytes(4, "little") + compact_size(len(tx.inputs))
    for txin in tx.inputs:
        out += txin.prev_txid + txin.prev_index.to_bytes(4, "little")
        out += ser_string(txin.script_sig) + txin.sequence.to_bytes(4, "little")
    out += compact_size(len(tx.outputs)) + b"".join(o.serialize() for o in tx.outputs)
    return out + tx.locktime.to_bytes(4, "little")


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_parser_round_trips_the_unsigned_transaction(case: dict) -> None:
    raw = bytes.fromhex(case["unsigned_tx"])
    assert _reserialize_legacy(parse_transaction(raw)) == raw


# --- malformed / boundary input -----------------------------------------------------------------

def test_invalid_hash_type_is_rejected() -> None:
    tx, index, script_code, amount, _ = _case(CASES[0])
    for bad in (0x00, 0x04, 0x7F, 0x80, 0x84, 0x100, -1):
        with pytest.raises(ValueError, match="hash type"):
            bip143_sighash(tx, index, script_code, amount, bad)


def test_input_index_out_of_range_is_rejected() -> None:
    tx, _, script_code, amount, hash_type = _case(CASES[0])
    for bad in (-1, len(tx.inputs), len(tx.inputs) + 5):
        with pytest.raises(ValueError, match="input index"):
            bip143_sighash(tx, bad, script_code, amount, hash_type)
        with pytest.raises(ValueError, match="input index"):
            bip143_precomputed_hashes(tx, bad, hash_type)


def test_bad_amount_is_rejected() -> None:
    tx, index, script_code, _, hash_type = _case(CASES[0])
    for bad in (-1, 1 << 64, 2**100):
        with pytest.raises(ValueError, match="amount"):
            bip143_sighash(tx, index, script_code, bad, hash_type)
    with pytest.raises(ValueError, match="amount"):
        bip143_sighash(tx, index, script_code, 1.0, hash_type)  # type: ignore[arg-type]


def test_non_bytes_script_code_is_rejected() -> None:
    tx, index, _, amount, hash_type = _case(CASES[0])
    with pytest.raises(TypeError, match="script_code"):
        bip143_sighash(tx, index, "76a914", amount, hash_type)  # type: ignore[arg-type]


def test_truncated_and_trailing_transaction_bytes_are_rejected() -> None:
    raw = bytes.fromhex(CASES[0]["unsigned_tx"])
    with pytest.raises(ValueError, match="truncated"):
        parse_transaction(raw[:-4])
    with pytest.raises(ValueError, match="trailing bytes"):
        parse_transaction(raw + b"\x00")
    with pytest.raises(TypeError):
        parse_transaction("not bytes")  # type: ignore[arg-type]


# --- Hypothesis / invariants --------------------------------------------------------------------

_HASH_TYPES = st.sampled_from([0x01, 0x02, 0x03, 0x81, 0x82, 0x83])


def _random_tx(draw: st.DrawFn) -> tx_mod.Transaction:
    n_in = draw(st.integers(1, 3))
    n_out = draw(st.integers(1, 3))
    inputs = tuple(
        TxIn(draw(st.binary(min_size=32, max_size=32)), draw(st.integers(0, 2**32 - 1)),
             b"", draw(st.integers(0, 2**32 - 1)))
        for _ in range(n_in)
    )
    outputs = tuple(
        TxOut(draw(st.integers(0, 2**63)), draw(st.binary(min_size=0, max_size=10)))
        for _ in range(n_out)
    )
    return tx_mod.Transaction(draw(st.integers(0, 2**32 - 1)), inputs, outputs, draw(st.integers(0, 2**32 - 1)))


@given(st.data(), _HASH_TYPES)
@FAST
def test_sighash_is_32_bytes_and_deterministic(data: st.DataObject, hash_type: int) -> None:
    tx = _random_tx(data.draw)
    index = data.draw(st.integers(0, len(tx.inputs) - 1))
    script_code = data.draw(st.binary(min_size=1, max_size=40))
    amount = data.draw(st.integers(0, (1 << 64) - 1))
    first = bip143_sighash(tx, index, script_code, amount, hash_type)
    second = bip143_sighash(tx, index, script_code, amount, hash_type)
    assert first == second and len(first) == 32


@given(st.data(), _HASH_TYPES)
@FAST
def test_zeroing_rules_hold(data: st.DataObject, hash_type: int) -> None:
    tx = _random_tx(data.draw)
    index = data.draw(st.integers(0, len(tx.inputs) - 1))
    hashes = bip143_precomputed_hashes(tx, index, hash_type)
    zero = b"\x00" * 32
    base = hash_type & 0x1F
    if hash_type & SIGHASH_ANYONECANPAY:
        assert hashes["hashPrevouts"] == zero and hashes["hashSequence"] == zero
    if base in (SIGHASH_SINGLE, SIGHASH_NONE):
        assert hashes["hashSequence"] == zero
    if base == SIGHASH_NONE:
        assert hashes["hashOutputs"] == zero
