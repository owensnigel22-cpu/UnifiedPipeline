"""Local BIP-143 signature verification for P2WPKH input witnesses."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from keylab.ec import secp256k1
from keylab.ec.sec1 import parse_sec1
from keylab.encoding.transaction import (
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    Transaction,
    TxOut,
    bip143_sighash,
    parse_transaction,
)

_VALID_SIGHASH_TYPES = frozenset({
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ALL | SIGHASH_ANYONECANPAY,
    SIGHASH_NONE | SIGHASH_ANYONECANPAY,
    SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
})


def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _decode_der_signature(signature: bytes) -> tuple[int, int] | None:
    if not 8 <= len(signature) <= 72 or signature[0] != 0x30:
        return None
    if signature[1] != len(signature) - 2 or signature[2] != 0x02:
        return None

    r_length = signature[3]
    r_start = 4
    r_end = r_start + r_length
    if r_length == 0 or r_end + 2 > len(signature) or signature[r_end] != 0x02:
        return None
    s_length = signature[r_end + 1]
    s_start = r_end + 2
    s_end = s_start + s_length
    if s_length == 0 or s_end != len(signature):
        return None

    r_bytes = signature[r_start:r_end]
    s_bytes = signature[s_start:s_end]
    for value in (r_bytes, s_bytes):
        if value[0] & 0x80:
            return None
        if len(value) > 1 and value[0] == 0 and not value[1] & 0x80:
            return None

    return int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")


def _p2wpkh_script_code(txin_script: bytes, script_pubkey: bytes) -> tuple[bytes, bytes] | None:
    if len(script_pubkey) == 22 and script_pubkey[:2] == b"\x00\x14":
        if txin_script:
            return None
        pubkey_hash = script_pubkey[2:]
    elif (
        len(script_pubkey) == 23
        and script_pubkey[:2] == b"\xa9\x14"
        and script_pubkey[-1:] == b"\x87"
    ):
        if len(txin_script) != 23 or txin_script[0] != 22:
            return None
        redeem_script = txin_script[1:]
        if redeem_script[:2] != b"\x00\x14" or _hash160(redeem_script) != script_pubkey[2:22]:
            return None
        pubkey_hash = redeem_script[2:]
    else:
        return None

    return b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac", pubkey_hash


def verify_p2wpkh_input(tx: Transaction, input_index: int, spent_output: TxOut) -> bool:
    """Verify one P2WPKH or P2SH-P2WPKH input against its supplied spent output.

    ``spent_output`` must be obtained from a trusted local source or independently
    authenticated by the caller. This function checks the witness signature, not
    UTXO provenance, script execution, or Bitcoin consensus validity.
    """
    if type(input_index) is not int or not 0 <= input_index < len(tx.inputs):
        return False

    txin = tx.inputs[input_index]
    if len(txin.witness) != 2:
        return False
    signature_with_type, public_key = txin.witness
    if len(signature_with_type) < 2 or len(public_key) != 33:
        return False

    hash_type = signature_with_type[-1]
    if hash_type not in _VALID_SIGHASH_TYPES:
        return False
    decoded = _decode_der_signature(signature_with_type[:-1])
    if decoded is None:
        return False

    context = _p2wpkh_script_code(txin.script_sig, spent_output.script_pubkey)
    if context is None:
        return False
    script_code, expected_pubkey_hash = context
    if _hash160(public_key) != expected_pubkey_hash:
        return False

    try:
        point = parse_sec1(public_key)
        digest = bip143_sighash(tx, input_index, script_code, spent_output.amount, hash_type)
    except (TypeError, ValueError, OverflowError):
        return False
    return secp256k1.ecdsa_verify_digest(digest, decoded, point)


def verify_transaction_signatures(raw_transaction: bytes, spent_outputs: Sequence[TxOut]) -> bool:
    """Verify every input in a transaction using caller-supplied spent outputs.

    The supported scope is P2WPKH and P2SH-P2WPKH (BIP-143). The spent-output
    sequence must be in transaction input order and must be independently
    authenticated; explorer-provided values alone do not establish provenance.
    This is signature checking only, not full script or consensus validation.
    """
    tx = parse_transaction(raw_transaction)
    if not tx.inputs or len(spent_outputs) != len(tx.inputs):
        raise ValueError("exactly one spent output is required for every transaction input")
    return all(
        verify_p2wpkh_input(tx, index, spent_output)
        for index, spent_output in enumerate(spent_outputs)
    )


__all__ = ["verify_p2wpkh_input", "verify_transaction_signatures"]
