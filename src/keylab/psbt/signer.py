"""BIP-174 Signer role for P2WPKH and P2SH-P2WPKH inputs.

This module implements only the **Signer** role from BIP-174: given a PSBT and
private key material, it computes the BIP-143 witness-v0 signature hash for an
input, signs it with the existing deterministic ECDSA primitive, and inserts a
``PSBT_IN_PARTIAL_SIG`` (type ``0x02``) record. It supports exactly two input
types -- native P2WPKH and P2SH-nested P2WPKH -- and nothing else.

It does **not** finalize, extract, combine/merge, broadcast, manage keys, or
cover P2WSH / Taproot / multisig. Sighashing is delegated to
:mod:`keylab.encoding.transaction` (the single transaction model); signing to
:func:`keylab.ec.secp256k1.ecdsa_sign_digest` (RFC 6979, low-S). See SECURITY.md.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Iterable

from keylab.ec import secp256k1
from keylab.encoding.transaction import (
    SIGHASH_ALL,
    Transaction,
    _Reader,
    bip143_sighash,
    parse_transaction,
)
from keylab.psbt.model import (
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_WITNESS_UTXO,
    KeyPair,
    Psbt,
    PsbtError,
    PsbtMap,
)
from keylab.psbt.validator import validate

_VALID_SIGHASH = frozenset({0x01, 0x02, 0x03, 0x81, 0x82, 0x83})


class PsbtSignError(PsbtError):
    """Raised when a PSBT input cannot be signed as requested (a subclass of :class:`PsbtError`)."""


def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _coerce_scalar(private_key: int | bytes) -> int:
    """Return a validated secp256k1 private scalar from an int or 32 big-endian bytes."""
    if isinstance(private_key, (bytes, bytearray)):
        if len(private_key) != 32:
            raise PsbtSignError("private key bytes must be exactly 32 bytes")
        scalar = int.from_bytes(private_key, "big")
    elif type(private_key) is int:
        scalar = private_key
    else:
        raise PsbtSignError("private key must be an int or 32 bytes")
    if not 1 <= scalar < secp256k1.N:
        raise PsbtSignError("private key must be an integer in [1, N-1]")
    return scalar


def _der_encode(r: int, s: int) -> bytes:
    """DER-encode an ECDSA signature ``(r, s)`` as Bitcoin serializes it."""
    def _int(value: int) -> bytes:
        body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if body[0] & 0x80:  # prepend 0x00 so the value stays positive
            body = b"\x00" + body
        return b"\x02" + bytes([len(body)]) + body
    payload = _int(r) + _int(s)
    return b"\x30" + bytes([len(payload)]) + payload


def _parse_witness_utxo(value: bytes) -> tuple[int, bytes]:
    """Parse a ``PSBT_IN_WITNESS_UTXO`` value into ``(amount, script_pubkey)``."""
    if len(value) < 8:
        raise PsbtSignError("witness UTXO record is truncated")
    amount = int.from_bytes(value[:8], "little")
    reader = _Reader(value[8:])
    try:
        script_pubkey = reader.string()
    except ValueError as exc:
        raise PsbtSignError(f"malformed witness UTXO script: {exc}") from exc
    if reader.offset != len(reader.data):
        raise PsbtSignError("trailing bytes in witness UTXO record")
    return amount, script_pubkey


def _input_signing_context(inp: PsbtMap) -> tuple[int, bytes, bytes]:
    """Return ``(amount, script_code, pubkey_hash)`` for a P2WPKH / P2SH-P2WPKH input.

    Raises :class:`PsbtSignError` if the input lacks the witness UTXO (or, for a
    P2SH input, the redeem script), or is not one of the two supported types.
    """
    witness_utxo = inp.get(PSBT_IN_WITNESS_UTXO)
    if witness_utxo is None:
        raise PsbtSignError("input is missing the witness UTXO (type 0x01) required to sign")
    amount, script_pubkey = _parse_witness_utxo(witness_utxo)

    if len(script_pubkey) == 22 and script_pubkey[0] == 0x00 and script_pubkey[1] == 0x14:
        pubkey_hash = script_pubkey[2:]  # native P2WPKH: scriptPubKey is the witness program
    elif len(script_pubkey) == 23 and script_pubkey[0] == 0xA9 and script_pubkey[1] == 0x14 and script_pubkey[22] == 0x87:
        redeem_script = inp.get(PSBT_IN_REDEEM_SCRIPT)
        if redeem_script is None:
            raise PsbtSignError("P2SH input is missing the redeem script (type 0x04)")
        if _hash160(redeem_script) != script_pubkey[2:22]:
            raise PsbtSignError("redeem script does not hash to the P2SH scriptPubKey")
        if not (len(redeem_script) == 22 and redeem_script[0] == 0x00 and redeem_script[1] == 0x14):
            raise PsbtSignError("unsupported redeem script (only P2SH-P2WPKH is supported)")
        pubkey_hash = redeem_script[2:]
    else:
        raise PsbtSignError("unsupported input type (only P2WPKH and P2SH-P2WPKH are supported)")

    script_code = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"  # the implied P2PKH script (BIP-143)
    return amount, script_code, pubkey_hash


def _effective_sighash(inp: PsbtMap, requested: int) -> int:
    """Resolve the sighash type: an input's own ``PSBT_IN_SIGHASH_TYPE`` record wins."""
    record = inp.get(PSBT_IN_SIGHASH_TYPE)
    if record is not None:
        if len(record) != 4:
            raise PsbtSignError("sighash-type record must be 4 bytes")
        sighash = int.from_bytes(record, "little")
        if requested != SIGHASH_ALL and requested != sighash:
            raise PsbtSignError("requested sighash type conflicts with the input's sighash-type record")
    else:
        sighash = requested
    if sighash not in _VALID_SIGHASH:
        raise PsbtSignError(f"unsupported sighash type: {sighash}")
    return sighash


def _clone(psbt: Psbt) -> Psbt:
    return Psbt(
        global_map=copy.deepcopy(psbt.global_map),
        inputs=[copy.deepcopy(m) for m in psbt.inputs],
        outputs=[copy.deepcopy(m) for m in psbt.outputs],
    )


def _unsigned_tx(psbt: Psbt) -> Transaction:
    raw = psbt.unsigned_tx_bytes
    if raw is None:
        raise PsbtSignError("PSBT has no unsigned transaction")
    return parse_transaction(raw)


def sign_input(psbt: Psbt, index: int, private_key: int | bytes, *, sighash_type: int = SIGHASH_ALL) -> Psbt:
    """Sign input ``index`` with ``private_key`` and return a new PSBT with the partial signature added.

    The input must be a P2WPKH or P2SH-P2WPKH input whose witness UTXO (and, for
    P2SH, redeem script) is present, and ``private_key`` must correspond to that
    input's public key. Raises :class:`PsbtSignError` on any mismatch; the input
    PSBT is never mutated.
    """
    validate(psbt)
    if not 0 <= index < len(psbt.inputs):
        raise PsbtSignError("input index is out of range")
    scalar = _coerce_scalar(private_key)
    tx = _unsigned_tx(psbt)
    inp = psbt.inputs[index]
    amount, script_code, pubkey_hash = _input_signing_context(inp)

    point = secp256k1.public_key_from_private_scalar(scalar)
    pubkey = secp256k1.compress_pubkey(point)
    if _hash160(pubkey) != pubkey_hash:
        raise PsbtSignError("signing key does not match this input's public key")

    partial_key = bytes([PSBT_IN_PARTIAL_SIG]) + pubkey
    if any(pair.key == partial_key for pair in inp.pairs):
        raise PsbtSignError("input already has a partial signature for this public key")

    sighash = _effective_sighash(inp, sighash_type)
    digest = bip143_sighash(tx, index, script_code, amount, sighash)
    r, s = secp256k1.ecdsa_sign_digest(digest, scalar)
    if secp256k1.is_high_s_signature((r, s)):  # defensive: the primitive already low-S normalizes
        raise PsbtSignError("internal error: signature is not low-S")
    if not secp256k1.ecdsa_verify_digest(digest, (r, s), point):
        raise PsbtSignError("internal error: produced signature failed verification")

    signature = _der_encode(r, s) + bytes([sighash])
    signed = _clone(psbt)
    signed.inputs[index].pairs.append(KeyPair(partial_key, signature))
    return signed


def signable_inputs(psbt: Psbt, keys: Iterable[int | bytes]) -> list[int]:
    """Return the indices of P2WPKH / P2SH-P2WPKH inputs one of ``keys`` can sign (and has not yet)."""
    hashes = {}
    for key in keys:
        scalar = _coerce_scalar(key)
        pubkey = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(scalar))
        hashes[_hash160(pubkey)] = pubkey
    result = []
    for index, inp in enumerate(psbt.inputs):
        try:
            _, _, pubkey_hash = _input_signing_context(inp)
        except PsbtSignError:
            continue
        matched = hashes.get(pubkey_hash)
        if matched is None:
            continue
        if any(pair.key == bytes([PSBT_IN_PARTIAL_SIG]) + matched for pair in inp.pairs):
            continue
        result.append(index)
    return result


def sign(psbt: Psbt, keys: Iterable[int | bytes], *, sighash_type: int = SIGHASH_ALL) -> Psbt:
    """Sign every input that one of ``keys`` can sign, returning a new PSBT.

    This is the BIP-174 "sign what you can" behaviour: inputs that are not
    P2WPKH / P2SH-P2WPKH, lack the data to sign, or match none of ``keys`` are
    left untouched. Existing partial signatures are preserved. The input PSBT is
    never mutated.
    """
    key_list = [_coerce_scalar(key) for key in keys]
    by_hash: dict[bytes, int] = {}
    for scalar in key_list:
        pubkey = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(scalar))
        by_hash[_hash160(pubkey)] = scalar

    result = psbt
    for index, inp in enumerate(psbt.inputs):
        try:
            _, _, pubkey_hash = _input_signing_context(inp)
        except PsbtSignError:
            continue
        matched_scalar = by_hash.get(pubkey_hash)
        if matched_scalar is None:
            continue
        pubkey = secp256k1.compress_pubkey(secp256k1.public_key_from_private_scalar(matched_scalar))
        if any(pair.key == bytes([PSBT_IN_PARTIAL_SIG]) + pubkey for pair in inp.pairs):
            continue
        result = sign_input(result, index, matched_scalar, sighash_type=sighash_type)
    return result


__all__ = [
    "PsbtSignError",
    "sign",
    "sign_input",
    "signable_inputs",
]
