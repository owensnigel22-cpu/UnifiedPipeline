"""BIP-174 Extractor role: build the final network transaction from a finalized PSBT.

Given a PSBT whose inputs are all finalized (M4.4), this module assembles the
final transaction by injecting each input's ``PSBT_IN_FINAL_SCRIPTSIG``
(``0x07``) into its ``scriptSig`` and ``PSBT_IN_FINAL_SCRIPTWITNESS`` (``0x08``)
into its witness, then serializes it with
:func:`keylab.encoding.transaction.serialize_transaction` (BIP-144 when any
input has witness data).

It performs no cryptography: it neither signs nor verifies, only rearranges
bytes already present in the finalized PSBT. It does not broadcast, combine, or
merge, and supports only the P2WPKH / P2SH-P2WPKH inputs the signer/finalizer
produce. The input PSBT is never mutated. See SECURITY.md.
"""

from __future__ import annotations

from keylab.encoding.transaction import (
    Transaction,
    TxIn,
    _Reader,
    parse_transaction,
    serialize_transaction,
)
from keylab.psbt.model import (
    PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    Psbt,
    PsbtError,
    PsbtMap,
)


class PsbtExtractError(PsbtError):
    """Raised when a transaction cannot be extracted from a PSBT (a subclass of :class:`PsbtError`)."""


def _decode_witness(value: bytes) -> tuple[bytes, ...]:
    """Decode a serialized witness stack (count-prefixed, each item length-prefixed)."""
    reader = _Reader(value)
    try:
        count = reader.compact()
        items = tuple(reader.string() for _ in range(count))
    except ValueError as exc:
        raise PsbtExtractError(f"malformed final scriptWitness: {exc}") from exc
    if reader.offset != len(reader.data):
        raise PsbtExtractError("trailing bytes in final scriptWitness")
    return items


def _input_is_finalized(inp: PsbtMap) -> bool:
    types = inp.types()
    return PSBT_IN_FINAL_SCRIPTSIG in types or PSBT_IN_FINAL_SCRIPTWITNESS in types


def extract_transaction(psbt: Psbt) -> Transaction:
    """Assemble the final :class:`Transaction` from a fully finalized PSBT.

    Raises :class:`PsbtExtractError` unless every input carries a finalized
    scriptSig and/or scriptWitness. The input PSBT is never mutated.
    """
    raw = psbt.unsigned_tx_bytes
    if raw is None:
        raise PsbtExtractError("PSBT has no unsigned transaction")
    tx = parse_transaction(raw)
    if len(psbt.inputs) != len(tx.inputs):
        raise PsbtExtractError("input map count does not match the unsigned transaction")

    final_inputs = []
    for index, (txin, inp) in enumerate(zip(tx.inputs, psbt.inputs, strict=True)):
        if not _input_is_finalized(inp):
            raise PsbtExtractError(f"input {index} is not finalized")
        script_sig = inp.get(PSBT_IN_FINAL_SCRIPTSIG) or b""
        witness_value = inp.get(PSBT_IN_FINAL_SCRIPTWITNESS)
        witness = _decode_witness(witness_value) if witness_value is not None else ()
        final_inputs.append(TxIn(
            prev_txid=txin.prev_txid,
            prev_index=txin.prev_index,
            script_sig=script_sig,
            sequence=txin.sequence,
            witness=witness,
        ))
    return Transaction(tx.version, tuple(final_inputs), tx.outputs, tx.locktime)


def extract(psbt: Psbt) -> bytes:
    """Return the final network-serialized (BIP-144) transaction from a finalized PSBT."""
    return serialize_transaction(extract_transaction(psbt))


__all__ = [
    "PsbtExtractError",
    "extract",
    "extract_transaction",
]
