"""BIP-174 PSBT parser/serializer/validator against the official vectors.

The official invalid/valid PSBT lists are the oracle: every invalid vector must
be rejected, and every valid vector must parse, validate, and re-serialize to the
exact input bytes. No signing, finalizing, or extraction is exercised.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from keylab import psbt
from keylab.encoding.transaction import compact_size
from keylab.psbt.model import KeyPair, PsbtMap

FAST = settings(max_examples=50, deadline=None)

_VEC = json.loads((Path(__file__).parent / "vectors" / "bip174_psbt_vectors.json").read_text(encoding="utf-8"))
VALID = [(c["case"], c["hex"]) for c in _VEC["valid"]]
INVALID = [(c["case"], c["hex"]) for c in _VEC["invalid"]]

# Minimal valid PSBT: global unsigned tx with 0 inputs / 0 outputs, no input/output maps.
_MIN_TX = bytes.fromhex("02000000" "00" "00" "00000000")  # version, 0 in, 0 out, locktime
MINIMAL = psbt.PSBT_MAGIC + b"\x01\x00" + compact_size(len(_MIN_TX)) + _MIN_TX + b"\x00"


def _record(key: bytes, value: bytes) -> bytes:
    return compact_size(len(key)) + key + compact_size(len(value)) + value


# --- official vectors ---------------------------------------------------------------------------

@pytest.mark.parametrize("case,hexstr", VALID, ids=[c for c, _ in VALID])
def test_valid_vector_parses_validates_and_round_trips(case: str, hexstr: str) -> None:
    raw = bytes.fromhex(hexstr)
    parsed = psbt.parse(raw)  # deserialize + validate
    assert psbt.serialize(parsed) == raw  # byte-exact round trip


@pytest.mark.parametrize("case,hexstr", INVALID, ids=[c for c, _ in INVALID])
def test_invalid_vector_is_rejected(case: str, hexstr: str) -> None:
    with pytest.raises(psbt.PsbtError):
        psbt.parse(bytes.fromhex(hexstr))


def test_deserialize_without_validate_still_round_trips_every_valid_vector() -> None:
    for _case, hexstr in VALID:
        raw = bytes.fromhex(hexstr)
        assert psbt.serialize(psbt.deserialize(raw)) == raw


# --- minimal / empty maps -----------------------------------------------------------------------

def test_minimal_psbt_has_empty_input_and_output_maps() -> None:
    parsed = psbt.parse(MINIMAL)
    assert parsed.inputs == [] and parsed.outputs == []
    assert parsed.global_map.get(psbt.model.PSBT_GLOBAL_UNSIGNED_TX) == _MIN_TX
    assert psbt.serialize(parsed) == MINIMAL


# --- structural rejection -----------------------------------------------------------------------

def test_bad_magic_is_rejected() -> None:
    with pytest.raises(psbt.PsbtError, match="magic"):
        psbt.deserialize(b"xxxx\xff" + MINIMAL[5:])


def test_missing_unsigned_tx_is_rejected() -> None:
    # Global map containing only an unknown key, no 0x00 unsigned tx.
    body = psbt.PSBT_MAGIC + _record(b"\x0f", b"data") + b"\x00"
    with pytest.raises(psbt.PsbtError, match="unsigned transaction"):
        psbt.deserialize(body)


def test_duplicate_key_is_rejected() -> None:
    dup = psbt.PSBT_MAGIC + b"\x01\x00" + compact_size(len(_MIN_TX)) + _MIN_TX \
        + _record(b"\x0f", b"a") + _record(b"\x0f", b"b") + b"\x00"
    with pytest.raises(psbt.PsbtError, match="duplicate"):
        psbt.deserialize(dup)


def test_truncated_record_is_rejected() -> None:
    with pytest.raises(psbt.PsbtError):
        psbt.deserialize(MINIMAL[:-1])  # separator dropped -> runs off the end


def test_trailing_bytes_are_rejected() -> None:
    with pytest.raises(psbt.PsbtError, match="trailing"):
        psbt.deserialize(MINIMAL + b"\x00")


def test_non_canonical_compactsize_is_rejected() -> None:
    # Key length 1 encoded as 0xfd 0x01 0x00 (should be a single 0x01 byte).
    bad = psbt.PSBT_MAGIC + b"\xfd\x01\x00" + b"\x00" + compact_size(len(_MIN_TX)) + _MIN_TX + b"\x00"
    with pytest.raises(psbt.PsbtError):
        psbt.deserialize(bad)


def test_non_bytes_input_raises_type_error() -> None:
    with pytest.raises(TypeError):
        psbt.deserialize("70736274ff")  # type: ignore[arg-type]


# --- unknown keys / boundary lengths ------------------------------------------------------------

def test_unknown_keys_are_preserved_and_round_trip() -> None:
    raw = psbt.PSBT_MAGIC + b"\x01\x00" + compact_size(len(_MIN_TX)) + _MIN_TX \
        + _record(b"\x0f", b"unknown-global") + b"\x00"
    parsed = psbt.parse(raw)
    assert parsed.global_map.get(0x0F) == b"unknown-global"
    assert psbt.serialize(parsed) == raw  # unknown key preserved verbatim


@pytest.mark.parametrize("value_len", [0, 1, 252, 253, 254, 65535, 65536])
def test_boundary_length_values_round_trip(value_len: int) -> None:
    value = b"\xab" * value_len
    raw = psbt.PSBT_MAGIC + b"\x01\x00" + compact_size(len(_MIN_TX)) + _MIN_TX \
        + _record(b"\x0f", value) + b"\x00"
    parsed = psbt.parse(raw)
    assert parsed.global_map.get(0x0F) == value
    assert psbt.serialize(parsed) == raw


# --- model accessors ----------------------------------------------------------------------------

def test_keypair_type_and_data_accessors() -> None:
    pair = KeyPair(key=b"\x06" + b"\x02" * 33, value=b"v")  # BIP32 derivation-shaped key
    assert pair.key_type == 0x06
    assert pair.key_data == b"\x02" * 33
    assert PsbtMap([pair]).get(0x06, b"\x02" * 33) == b"v"
    assert PsbtMap([pair]).get(0x06, b"\x03") is None


def test_empty_key_is_rejected_by_accessor() -> None:
    with pytest.raises(psbt.PsbtError):
        _ = KeyPair(key=b"", value=b"v").key_type


# --- regression ---------------------------------------------------------------------------------

def test_regression_first_valid_vector_structure() -> None:
    # "PSBT with one P2PKH input. Outputs are empty": the tx has 1 input and 2 outputs,
    # so there is 1 input map and 2 output maps, and the output maps carry no records.
    raw = bytes.fromhex(VALID[0][1])
    parsed = psbt.parse(raw)
    assert len(parsed.inputs) == 1
    assert len(parsed.outputs) == 2
    assert all(m.pairs == [] for m in parsed.outputs)  # "outputs are empty"
    assert parsed.global_map.get(psbt.model.PSBT_GLOBAL_UNSIGNED_TX) is not None


# --- Hypothesis ---------------------------------------------------------------------------------

@given(st.lists(st.tuples(st.integers(1, 120), st.binary(max_size=40)), max_size=6, unique_by=lambda t: t[0]))
@FAST
def test_round_trip_random_unknown_global_keys(items: list[tuple[int, bytes]]) -> None:
    # Build a PSBT whose global map carries the unsigned tx plus random unknown keys.
    body = bytearray(psbt.PSBT_MAGIC)
    body += _record(b"\x00", _MIN_TX)
    for key_type, value in items:
        if key_type in (0x00, 0xFB):  # reserved standard singletons -> skip to keep it valid
            continue
        body += _record(bytes([key_type]), value)
    body += b"\x00"
    raw = bytes(body)
    parsed = psbt.parse(raw)
    assert psbt.serialize(parsed) == raw


@given(st.binary(max_size=64))
@FAST
def test_random_bytes_never_crash(raw: bytes) -> None:
    # Arbitrary bytes either parse or raise PsbtError -- never an unexpected exception.
    try:
        psbt.parse(raw)
    except psbt.PsbtError:
        pass
