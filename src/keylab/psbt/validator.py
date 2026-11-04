"""BIP-174 semantic validation rules for a parsed :class:`Psbt`.

Checks that the global map carries a non-witness-serialized, genuinely *unsigned*
transaction, and that every standard key-type carries well-formed key data
(singleton types carry no key data; signature/derivation types carry a 33- or
65-byte public key). Unknown key types are permitted and untouched, so forward
compatibility is preserved. Structural rules (magic, CompactSize, duplicate keys,
truncation, map counts) are enforced earlier in :mod:`keylab.psbt.parser`.
"""

from __future__ import annotations

from keylab.encoding.transaction import Transaction, compact_size, parse_transaction, ser_string
from keylab.psbt.model import (
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_GLOBAL_VERSION,
    PSBT_IN_BIP32_DERIVATION,
    PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_NON_WITNESS_UTXO,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_WITNESS_SCRIPT,
    PSBT_IN_WITNESS_UTXO,
    PSBT_OUT_BIP32_DERIVATION,
    PSBT_OUT_REDEEM_SCRIPT,
    PSBT_OUT_WITNESS_SCRIPT,
    Psbt,
    PsbtError,
    PsbtMap,
)

_PUBKEY_LENGTHS = (33, 65)

# Standard key types whose key carries no key data (singletons).
_GLOBAL_EMPTY = frozenset({PSBT_GLOBAL_UNSIGNED_TX, PSBT_GLOBAL_VERSION})
_INPUT_EMPTY = frozenset({
    PSBT_IN_NON_WITNESS_UTXO, PSBT_IN_WITNESS_UTXO, PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_REDEEM_SCRIPT, PSBT_IN_WITNESS_SCRIPT,
    PSBT_IN_FINAL_SCRIPTSIG, PSBT_IN_FINAL_SCRIPTWITNESS,
})
_OUTPUT_EMPTY = frozenset({PSBT_OUT_REDEEM_SCRIPT, PSBT_OUT_WITNESS_SCRIPT})
# Standard key types whose key data must be a 33/65-byte public key.
_INPUT_PUBKEY = frozenset({PSBT_IN_PARTIAL_SIG, PSBT_IN_BIP32_DERIVATION})
_OUTPUT_PUBKEY = frozenset({PSBT_OUT_BIP32_DERIVATION})


def _check_map(psbt_map: PsbtMap, scope: str, empty: frozenset[int], pubkey: frozenset[int]) -> None:
    for pair in psbt_map.pairs:
        key_type = pair.key_type
        if key_type in empty and pair.key_data:
            raise PsbtError(f"{scope} key type {key_type:#x} must have no key data")
        if key_type in pubkey and len(pair.key_data) not in _PUBKEY_LENGTHS:
            raise PsbtError(f"{scope} key type {key_type:#x} must carry a 33- or 65-byte public key")


def _serialize_tx_legacy(tx: Transaction) -> bytes:
    """Non-witness (legacy) serialization of ``tx`` for the unsigned-tx shape check."""
    out = bytearray(tx.version.to_bytes(4, "little"))
    out += compact_size(len(tx.inputs))
    for txin in tx.inputs:
        out += txin.prev_txid + txin.prev_index.to_bytes(4, "little")
        out += ser_string(txin.script_sig) + txin.sequence.to_bytes(4, "little")
    out += compact_size(len(tx.outputs))
    for txout in tx.outputs:
        out += txout.amount.to_bytes(8, "little") + ser_string(txout.script_pubkey)
    out += tx.locktime.to_bytes(4, "little")
    return bytes(out)


def validate(psbt: Psbt) -> None:
    """Raise :class:`PsbtError` unless ``psbt`` satisfies the BIP-174 rules checked here."""
    tx_bytes = psbt.global_map.get(PSBT_GLOBAL_UNSIGNED_TX)
    if tx_bytes is None:
        raise PsbtError("global map is missing the unsigned transaction")
    tx = parse_transaction(tx_bytes)

    # The unsigned transaction must be in non-witness serialization...
    if _serialize_tx_legacy(tx) != tx_bytes:
        raise PsbtError("unsigned transaction must use non-witness serialization")
    # ...and must be genuinely unsigned: no scriptSigs, no witnesses.
    if any(txin.script_sig for txin in tx.inputs):
        raise PsbtError("unsigned transaction must have empty scriptSigs")
    if any(txin.witness for txin in tx.inputs):
        raise PsbtError("unsigned transaction must have no witness data")

    # One map per input and per output (structurally guaranteed by the parser).
    if len(psbt.inputs) != len(tx.inputs) or len(psbt.outputs) != len(tx.outputs):
        raise PsbtError("input/output map count does not match the unsigned transaction")

    _check_map(psbt.global_map, "global", _GLOBAL_EMPTY, frozenset())
    for input_map in psbt.inputs:
        _check_map(input_map, "input", _INPUT_EMPTY, _INPUT_PUBKEY)
    for output_map in psbt.outputs:
        _check_map(output_map, "output", _OUTPUT_EMPTY, _OUTPUT_PUBKEY)


__all__ = ["validate"]
