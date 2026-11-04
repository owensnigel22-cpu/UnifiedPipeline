"""BIP-174 PSBT deserialization (structural parse).

Reuses :class:`keylab.encoding.transaction._Reader` for canonical CompactSize
decoding and :func:`keylab.encoding.transaction.parse_transaction` for the
embedded unsigned transaction (which fixes the number of input and output maps).
Structural failures -- bad magic, truncation, non-canonical CompactSize,
duplicate keys within a map, a missing unsigned transaction, or trailing bytes --
raise :class:`PsbtError`. Semantic BIP-174 rules live in :mod:`keylab.psbt.validator`.
"""

from __future__ import annotations

from keylab.encoding.transaction import _Reader, parse_transaction
from keylab.psbt.model import (
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_MAGIC,
    KeyPair,
    Psbt,
    PsbtError,
    PsbtMap,
)


def _read_map(reader: _Reader) -> PsbtMap:
    """Read one key-value map up to its ``0x00`` separator, rejecting duplicate keys."""
    pairs: list[KeyPair] = []
    seen: set[bytes] = set()
    while True:
        key_len = reader.compact()
        if key_len == 0:  # 0x00 separator ends the map
            return PsbtMap(pairs)
        key = reader.take(key_len)
        value = reader.take(reader.compact())
        if key in seen:
            raise PsbtError(f"duplicate key in PSBT map: {key.hex()}")
        seen.add(key)
        pairs.append(KeyPair(key, value))


def deserialize(raw: bytes) -> Psbt:
    """Parse ``raw`` PSBT bytes into a :class:`Psbt`, preserving every record verbatim."""
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("PSBT must be bytes")
    reader = _Reader(bytes(raw))
    try:
        if reader.take(len(PSBT_MAGIC)) != PSBT_MAGIC:
            raise PsbtError("bad PSBT magic (not a PSBT)")
        global_map = _read_map(reader)
        tx_bytes = global_map.get(PSBT_GLOBAL_UNSIGNED_TX)
        if tx_bytes is None:
            raise PsbtError("global map is missing the unsigned transaction (type 0x00)")
        tx = parse_transaction(tx_bytes)
        inputs = [_read_map(reader) for _ in range(len(tx.inputs))]
        outputs = [_read_map(reader) for _ in range(len(tx.outputs))]
    except PsbtError:
        raise
    except (ValueError, KeyError, IndexError) as exc:
        raise PsbtError(f"malformed PSBT: {exc}") from exc
    if reader.offset != len(reader.data):
        raise PsbtError("trailing bytes after PSBT")
    return Psbt(global_map, inputs, outputs)


__all__ = ["deserialize"]
