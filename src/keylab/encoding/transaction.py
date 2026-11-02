"""Minimal Bitcoin transaction parsing and BIP-341 Taproot signature hashing.

This is a parser and hash calculator for study and test-vector verification.
It does not validate consensus rules, execute scripts, or build/broadcast
transactions.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from keylab.hashes.tagged import tagged_hash

SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80
_VALID_TAPROOT_HASH_TYPES = frozenset({0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83})
_VALID_BIP143_HASH_TYPES = frozenset({0x01, 0x02, 0x03, 0x81, 0x82, 0x83})


def compact_size(value: int) -> bytes:
    """Serialize Bitcoin's CompactSize unsigned integer."""
    if type(value) is not int or value < 0:
        raise ValueError("CompactSize value must be a non-negative integer")
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + value.to_bytes(8, "little")
    raise ValueError("CompactSize value exceeds 64 bits")


def ser_string(data: bytes) -> bytes:
    """Serialize bytes with a CompactSize length prefix."""
    return compact_size(len(data)) + data


@dataclass(frozen=True)
class TxOut:
    amount: int
    script_pubkey: bytes

    def serialize(self) -> bytes:
        return self.amount.to_bytes(8, "little") + ser_string(self.script_pubkey)


@dataclass(frozen=True)
class TxIn:
    prev_txid: bytes  # serialized (little-endian, "internal") byte order
    prev_index: int
    script_sig: bytes
    sequence: int
    witness: tuple[bytes, ...] = ()

    @property
    def outpoint(self) -> bytes:
        return self.prev_txid + self.prev_index.to_bytes(4, "little")


@dataclass(frozen=True)
class Transaction:
    version: int
    inputs: tuple[TxIn, ...]
    outputs: tuple[TxOut, ...]
    locktime: int


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.data):
            raise ValueError("transaction data is truncated")
        chunk = self.data[self.offset:self.offset + count]
        self.offset += count
        return chunk

    def uint(self, size: int) -> int:
        return int.from_bytes(self.take(size), "little")

    def compact(self) -> int:
        first = self.take(1)[0]
        if first < 0xFD:
            return first
        size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
        value = self.uint(size)
        if value < {2: 0xFD, 4: 0x10000, 8: 0x100000000}[size]:
            raise ValueError("non-canonical CompactSize encoding")
        return value

    def string(self) -> bytes:
        return self.take(self.compact())


def parse_transaction(raw: bytes) -> Transaction:
    """Parse a legacy or SegWit (BIP-144) serialized transaction."""
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("transaction must be bytes")
    reader = _Reader(bytes(raw))
    version = reader.uint(4)
    segwit = False
    if reader.data[reader.offset:reader.offset + 2] == b"\x00\x01":
        segwit = True
        reader.take(2)
    input_count = reader.compact()
    raw_inputs = []
    for _ in range(input_count):
        prev_txid = reader.take(32)
        prev_index = reader.uint(4)
        script_sig = reader.string()
        sequence = reader.uint(4)
        raw_inputs.append((prev_txid, prev_index, script_sig, sequence))
    outputs = tuple(TxOut(reader.uint(8), reader.string()) for _ in range(reader.compact()))
    witnesses: list[tuple[bytes, ...]] = [() for _ in raw_inputs]
    if segwit:
        witnesses = [tuple(reader.string() for _ in range(reader.compact())) for _ in raw_inputs]
    locktime = reader.uint(4)
    if reader.offset != len(reader.data):
        raise ValueError("trailing bytes after transaction")
    inputs = tuple(TxIn(*fields, witness=witness) for fields, witness in zip(raw_inputs, witnesses))
    return Transaction(version, inputs, outputs, locktime)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def taproot_precomputed_hashes(tx: Transaction, spent_outputs: Sequence[TxOut]) -> dict[str, bytes]:
    """Return BIP-341's single-SHA256 transaction-wide hashes."""
    if len(spent_outputs) != len(tx.inputs):
        raise ValueError("one spent output is required per transaction input")
    return {
        "hashPrevouts": _sha256(b"".join(txin.outpoint for txin in tx.inputs)),
        "hashAmounts": _sha256(b"".join(out.amount.to_bytes(8, "little") for out in spent_outputs)),
        "hashScriptPubkeys": _sha256(b"".join(ser_string(out.script_pubkey) for out in spent_outputs)),
        "hashSequences": _sha256(b"".join(txin.sequence.to_bytes(4, "little") for txin in tx.inputs)),
        "hashOutputs": _sha256(b"".join(out.serialize() for out in tx.outputs)),
    }


def taproot_signature_message(
    tx: Transaction,
    input_index: int,
    spent_outputs: Sequence[TxOut],
    hash_type: int = SIGHASH_DEFAULT,
    *,
    annex: bytes | None = None,
    leaf_hash: bytes | None = None,
    codesep_pos: int = 0xFFFFFFFF,
) -> bytes:
    """Return ``0x00 || SigMsg(hash_type, ext_flag)`` from BIP-341 (and BIP-342 extension).

    The leading 0x00 is the sighash epoch. Supplying ``leaf_hash`` selects the
    script-path extension (ext_flag = 1) with key_version 0 and ``codesep_pos``.
    """
    if hash_type not in _VALID_TAPROOT_HASH_TYPES:
        raise ValueError("invalid Taproot hash type")
    if not 0 <= input_index < len(tx.inputs):
        raise ValueError("input index is out of range")
    if len(spent_outputs) != len(tx.inputs):
        raise ValueError("one spent output is required per transaction input")
    if annex is not None and (not annex or annex[0] != 0x50):
        raise ValueError("annex must start with 0x50")
    if leaf_hash is not None and len(leaf_hash) != 32:
        raise ValueError("leaf hash must be 32 bytes")

    output_type = SIGHASH_ALL if hash_type == SIGHASH_DEFAULT else hash_type & 0x03
    anyone_can_pay = bool(hash_type & SIGHASH_ANYONECANPAY)
    hashes = taproot_precomputed_hashes(tx, spent_outputs)

    message = bytes([0x00, hash_type])
    message += tx.version.to_bytes(4, "little") + tx.locktime.to_bytes(4, "little")
    if not anyone_can_pay:
        message += (hashes["hashPrevouts"] + hashes["hashAmounts"]
                    + hashes["hashScriptPubkeys"] + hashes["hashSequences"])
    if output_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        message += hashes["hashOutputs"]
    ext_flag = 1 if leaf_hash is not None else 0
    message += bytes([ext_flag * 2 + (annex is not None)])
    if anyone_can_pay:
        txin = tx.inputs[input_index]
        spent = spent_outputs[input_index]
        message += (txin.outpoint + spent.amount.to_bytes(8, "little")
                    + ser_string(spent.script_pubkey) + txin.sequence.to_bytes(4, "little"))
    else:
        message += input_index.to_bytes(4, "little")
    if annex is not None:
        message += _sha256(ser_string(annex))
    if output_type == SIGHASH_SINGLE:
        if input_index >= len(tx.outputs):
            raise ValueError("SIGHASH_SINGLE requires a matching output")
        message += _sha256(tx.outputs[input_index].serialize())
    if leaf_hash is not None:
        message += leaf_hash + b"\x00" + codesep_pos.to_bytes(4, "little")
    return message


def taproot_sighash(
    tx: Transaction,
    input_index: int,
    spent_outputs: Sequence[TxOut],
    hash_type: int = SIGHASH_DEFAULT,
    *,
    annex: bytes | None = None,
    leaf_hash: bytes | None = None,
    codesep_pos: int = 0xFFFFFFFF,
) -> bytes:
    """Return the 32-byte BIP-341 signature hash ``hash_TapSighash(0x00 || SigMsg)``."""
    return tagged_hash("TapSighash", taproot_signature_message(
        tx, input_index, spent_outputs, hash_type,
        annex=annex, leaf_hash=leaf_hash, codesep_pos=codesep_pos,
    ))


def bip143_precomputed_hashes(tx: Transaction, input_index: int, hash_type: int) -> dict[str, bytes]:
    """Return BIP-143's ``hashPrevouts``/``hashSequence``/``hashOutputs`` for this input.

    Each is the double-SHA256 the preimage actually commits to for ``hash_type``,
    i.e. with the ANYONECANPAY/NONE/SINGLE zeroing rules already applied (a zeroed
    field is 32 zero bytes). The three may be reused across inputs of the same
    transaction that share a hash type.
    """
    if hash_type not in _VALID_BIP143_HASH_TYPES:
        raise ValueError("invalid BIP-143 hash type")
    if not 0 <= input_index < len(tx.inputs):
        raise ValueError("input index is out of range")
    anyone_can_pay = bool(hash_type & SIGHASH_ANYONECANPAY)
    base_type = hash_type & 0x1F
    zero = b"\x00" * 32

    hash_prevouts = zero
    if not anyone_can_pay:
        hash_prevouts = _dsha256(b"".join(txin.outpoint for txin in tx.inputs))

    hash_sequence = zero
    if not anyone_can_pay and base_type not in (SIGHASH_SINGLE, SIGHASH_NONE):
        hash_sequence = _dsha256(b"".join(txin.sequence.to_bytes(4, "little") for txin in tx.inputs))

    if base_type not in (SIGHASH_SINGLE, SIGHASH_NONE):
        hash_outputs = _dsha256(b"".join(out.serialize() for out in tx.outputs))
    elif base_type == SIGHASH_SINGLE and input_index < len(tx.outputs):
        hash_outputs = _dsha256(tx.outputs[input_index].serialize())
    else:
        hash_outputs = zero

    return {"hashPrevouts": hash_prevouts, "hashSequence": hash_sequence, "hashOutputs": hash_outputs}


def bip143_signature_message(
    tx: Transaction,
    input_index: int,
    script_code: bytes,
    amount: int,
    hash_type: int = SIGHASH_ALL,
) -> bytes:
    """Return BIP-143's witness-v0 sighash preimage for a P2WPKH/P2WSH-style input.

    ``script_code`` is the raw script the signature commits to, *without* a
    CompactSize length prefix (it is length-prefixed here, as Bitcoin serializes a
    script inside a CTxOut). For P2WPKH it is ``0x76a914{20-byte-hash}88ac``; for
    P2WSH it is the witnessScript, already reduced for any executed
    ``OP_CODESEPARATOR`` as BIP-143 specifies (this is a hash calculator, not a
    Script interpreter, so the caller supplies the reduced scriptCode). ``amount``
    is the value in satoshis of the output being spent.
    """
    if not 0 <= input_index < len(tx.inputs):
        raise ValueError("input index is out of range")
    if hash_type not in _VALID_BIP143_HASH_TYPES:
        raise ValueError("invalid BIP-143 hash type")
    if not isinstance(script_code, (bytes, bytearray)):
        raise TypeError("script_code must be bytes")
    if type(amount) is not int or not 0 <= amount < (1 << 64):
        raise ValueError("amount must be an unsigned 64-bit integer (satoshis)")

    hashes = bip143_precomputed_hashes(tx, input_index, hash_type)
    txin = tx.inputs[input_index]
    return b"".join((
        tx.version.to_bytes(4, "little"),
        hashes["hashPrevouts"],
        hashes["hashSequence"],
        txin.outpoint,
        ser_string(bytes(script_code)),
        amount.to_bytes(8, "little"),
        txin.sequence.to_bytes(4, "little"),
        hashes["hashOutputs"],
        tx.locktime.to_bytes(4, "little"),
        hash_type.to_bytes(4, "little"),
    ))


def bip143_sighash(
    tx: Transaction,
    input_index: int,
    script_code: bytes,
    amount: int,
    hash_type: int = SIGHASH_ALL,
) -> bytes:
    """Return the 32-byte BIP-143 witness-v0 signature hash (double-SHA256 of the preimage)."""
    return _dsha256(bip143_signature_message(tx, input_index, script_code, amount, hash_type))


__all__ = [
    "SIGHASH_ALL",
    "SIGHASH_ANYONECANPAY",
    "SIGHASH_DEFAULT",
    "SIGHASH_NONE",
    "SIGHASH_SINGLE",
    "Transaction",
    "TxIn",
    "TxOut",
    "bip143_precomputed_hashes",
    "bip143_sighash",
    "bip143_signature_message",
    "compact_size",
    "parse_transaction",
    "ser_string",
    "taproot_precomputed_hashes",
    "taproot_sighash",
    "taproot_signature_message",
]
