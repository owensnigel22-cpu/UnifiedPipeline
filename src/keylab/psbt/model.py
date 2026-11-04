"""Data model for BIP-174 Partially Signed Bitcoin Transactions (PSBT).

A PSBT is a magic prefix followed by a global key-value map, one input map per
transaction input, and one output map per transaction output. Each map is an
ordered list of ``<key><value>`` records terminated by a ``0x00`` separator;
``key`` is ``<keytype varint><keydata>``. This model preserves every record
verbatim -- including unknown key types -- so a parsed PSBT re-serializes to the
exact input bytes.

Parsing and validation only: this is not a wallet, signer, or broadcaster.
"""

from __future__ import annotations

from dataclasses import dataclass, field

PSBT_MAGIC = b"psbt\xff"

# Global key types (BIP-174).
PSBT_GLOBAL_UNSIGNED_TX = 0x00
PSBT_GLOBAL_XPUB = 0x01
PSBT_GLOBAL_VERSION = 0xFB
PSBT_GLOBAL_PROPRIETARY = 0xFC

# Input key types.
PSBT_IN_NON_WITNESS_UTXO = 0x00
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_PARTIAL_SIG = 0x02
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_REDEEM_SCRIPT = 0x04
PSBT_IN_WITNESS_SCRIPT = 0x05
PSBT_IN_BIP32_DERIVATION = 0x06
PSBT_IN_FINAL_SCRIPTSIG = 0x07
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08

# Output key types.
PSBT_OUT_REDEEM_SCRIPT = 0x00
PSBT_OUT_WITNESS_SCRIPT = 0x01
PSBT_OUT_BIP32_DERIVATION = 0x02


class PsbtError(ValueError):
    """Raised on a malformed PSBT or a BIP-174 validation failure."""


def _read_varint(data: bytes) -> tuple[int, int]:
    """Read a CompactSize at the start of ``data``; return (value, bytes_consumed)."""
    if not data:
        raise PsbtError("empty key: missing key type")
    first = data[0]
    if first < 0xFD:
        return first, 1
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    if len(data) < 1 + width:
        raise PsbtError("truncated CompactSize in key type")
    value = int.from_bytes(data[1:1 + width], "little")
    minimum = {2: 0xFD, 4: 0x10000, 8: 0x100000000}[width]
    if value < minimum:
        raise PsbtError("non-canonical CompactSize in key type")
    return value, 1 + width


@dataclass(frozen=True)
class KeyPair:
    """One ``<key><value>`` record. ``key`` includes the key-type varint and keydata."""

    key: bytes
    value: bytes

    @property
    def key_type(self) -> int:
        return _read_varint(self.key)[0]

    @property
    def key_data(self) -> bytes:
        return self.key[_read_varint(self.key)[1]:]


@dataclass
class PsbtMap:
    """An ordered PSBT key-value map (global, input, or output)."""

    pairs: list[KeyPair] = field(default_factory=list)

    def get(self, key_type: int, key_data: bytes = b"") -> bytes | None:
        """Return the value for ``(key_type, key_data)``, or ``None`` if absent."""
        for pair in self.pairs:
            if pair.key_type == key_type and pair.key_data == key_data:
                return pair.value
        return None

    def types(self) -> list[int]:
        return [pair.key_type for pair in self.pairs]


@dataclass
class Psbt:
    """A parsed PSBT: a global map plus one map per transaction input and output."""

    global_map: PsbtMap
    inputs: list[PsbtMap]
    outputs: list[PsbtMap]

    @property
    def unsigned_tx_bytes(self) -> bytes | None:
        return self.global_map.get(PSBT_GLOBAL_UNSIGNED_TX)


__all__ = [
    "PSBT_GLOBAL_PROPRIETARY",
    "PSBT_GLOBAL_UNSIGNED_TX",
    "PSBT_GLOBAL_VERSION",
    "PSBT_GLOBAL_XPUB",
    "PSBT_IN_BIP32_DERIVATION",
    "PSBT_IN_FINAL_SCRIPTSIG",
    "PSBT_IN_FINAL_SCRIPTWITNESS",
    "PSBT_IN_NON_WITNESS_UTXO",
    "PSBT_IN_PARTIAL_SIG",
    "PSBT_IN_REDEEM_SCRIPT",
    "PSBT_IN_SIGHASH_TYPE",
    "PSBT_IN_WITNESS_SCRIPT",
    "PSBT_IN_WITNESS_UTXO",
    "PSBT_MAGIC",
    "PSBT_OUT_BIP32_DERIVATION",
    "PSBT_OUT_REDEEM_SCRIPT",
    "PSBT_OUT_WITNESS_SCRIPT",
    "KeyPair",
    "Psbt",
    "PsbtError",
    "PsbtMap",
]
