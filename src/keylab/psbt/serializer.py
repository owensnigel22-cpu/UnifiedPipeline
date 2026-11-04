"""BIP-174 PSBT serialization.

Writes the magic prefix, the global map, and each input/output map, every record
as ``CompactSize(len(key)) || key || CompactSize(len(value)) || value`` followed
by the ``0x00`` map separator. Serializing a PSBT parsed by
:func:`keylab.psbt.parser.deserialize` reproduces the exact input bytes.
"""

from __future__ import annotations

from keylab.encoding.transaction import compact_size
from keylab.psbt.model import PSBT_MAGIC, Psbt, PsbtMap


def _serialize_map(psbt_map: PsbtMap) -> bytes:
    out = bytearray()
    for pair in psbt_map.pairs:
        out += compact_size(len(pair.key)) + pair.key
        out += compact_size(len(pair.value)) + pair.value
    out += b"\x00"  # map separator
    return bytes(out)


def serialize(psbt: Psbt) -> bytes:
    """Serialize a :class:`Psbt` back to raw BIP-174 bytes."""
    out = bytearray(PSBT_MAGIC)
    out += _serialize_map(psbt.global_map)
    for input_map in psbt.inputs:
        out += _serialize_map(input_map)
    for output_map in psbt.outputs:
        out += _serialize_map(output_map)
    return bytes(out)


__all__ = ["serialize"]
