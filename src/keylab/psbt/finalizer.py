"""BIP-174 Finalizer role for P2WPKH and P2SH-P2WPKH inputs.

This module implements only the BIP-174 **Finalizer** role for the two input
types the signer supports. Given a PSBT whose inputs already carry a valid
``PSBT_IN_PARTIAL_SIG``, it builds the final ``scriptWitness`` (type ``0x08``)
and, for P2SH-P2WPKH, the final ``scriptSig`` (type ``0x07``), then removes the
now-redundant signing fields (partial sig, sighash type, redeem/witness script,
BIP-32 derivation), keeping the UTXO and any proprietary/unknown records.

It consumes existing signatures only: it never creates a signature, never alters
the unsigned transaction, and never touches unrelated inputs. It does **not**
extract or broadcast a transaction, combine/merge PSBTs, or handle P2WSH /
Taproot / multisig. Signatures it accepts are verified against the BIP-143
sighash before an input is finalized. See SECURITY.md.
"""

from __future__ import annotations

import copy

from keylab.ec import secp256k1
from keylab.encoding.transaction import (
    Transaction,
    bip143_sighash,
    compact_size,
    parse_transaction,
    ser_string,
)
from keylab.psbt.model import (
    PSBT_IN_BIP32_DERIVATION,
    PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_WITNESS_SCRIPT,
    KeyPair,
    Psbt,
    PsbtError,
    PsbtMap,
)
from keylab.psbt.signer import PsbtSignError, _hash160, _input_signing_context
from keylab.psbt.validator import validate

# Input fields the Finalizer removes once an input is finalized (BIP-174).
_REDUNDANT_AFTER_FINALIZE = frozenset({
    PSBT_IN_PARTIAL_SIG,
    PSBT_IN_SIGHASH_TYPE,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_WITNESS_SCRIPT,
    PSBT_IN_BIP32_DERIVATION,
})
_VALID_SIGHASH = frozenset({0x01, 0x02, 0x03, 0x81, 0x82, 0x83})


class PsbtFinalizeError(PsbtError):
    """Raised when a PSBT input cannot be finalized (a subclass of :class:`PsbtError`)."""


def _der_decode(signature: bytes) -> tuple[int, int]:
    """Decode a DER ECDSA signature (without the trailing sighash byte) into ``(r, s)``."""
    if len(signature) < 8 or signature[0] != 0x30:
        raise PsbtFinalizeError("partial signature is not a DER sequence")
    if signature[1] != len(signature) - 2:
        raise PsbtFinalizeError("partial signature has a bad DER length")
    if signature[2] != 0x02:
        raise PsbtFinalizeError("partial signature is missing the r integer")
    r_len = signature[3]
    if 4 + r_len + 2 > len(signature):
        raise PsbtFinalizeError("partial signature r runs past the end")
    r = int.from_bytes(signature[4:4 + r_len], "big")
    s_marker = 4 + r_len
    if signature[s_marker] != 0x02:
        raise PsbtFinalizeError("partial signature is missing the s integer")
    s_len = signature[s_marker + 1]
    s_start = s_marker + 2
    if s_start + s_len != len(signature):
        raise PsbtFinalizeError("partial signature has trailing bytes")
    s = int.from_bytes(signature[s_start:s_start + s_len], "big")
    return r, s


def _is_finalized(inp: PsbtMap) -> bool:
    types = inp.types()
    return PSBT_IN_FINAL_SCRIPTSIG in types or PSBT_IN_FINAL_SCRIPTWITNESS in types


def _is_p2sh(inp: PsbtMap) -> bool:
    return inp.get(PSBT_IN_REDEEM_SCRIPT) is not None


def _matching_partial_sig(inp: PsbtMap, pubkey_hash: bytes) -> tuple[bytes, bytes]:
    """Return the ``(pubkey, signature)`` whose pubkey matches the input, or raise."""
    partials = [(pair.key_data, pair.value) for pair in inp.pairs if pair.key_type == PSBT_IN_PARTIAL_SIG]
    if not partials:
        raise PsbtFinalizeError("input has no partial signature to finalize")
    for pubkey, signature in partials:
        if _hash160(pubkey) == pubkey_hash:
            return pubkey, signature
    raise PsbtFinalizeError("no partial signature matches this input's public key")


def _unsigned_tx(psbt: Psbt) -> Transaction:
    raw = psbt.unsigned_tx_bytes
    if raw is None:
        raise PsbtFinalizeError("PSBT has no unsigned transaction")
    return parse_transaction(raw)


def _final_scriptwitness(signature: bytes, pubkey: bytes) -> bytes:
    """Serialize the P2WPKH witness stack ``<sig> <pubkey>`` (BIP-141 count-prefixed)."""
    return compact_size(2) + ser_string(signature) + ser_string(pubkey)


def finalize_input(psbt: Psbt, index: int, *, verify: bool = True) -> Psbt:
    """Finalize input ``index`` and return a new PSBT; raise :class:`PsbtFinalizeError` otherwise.

    The input must be an unfinalized P2WPKH or P2SH-P2WPKH input carrying a valid
    partial signature for its own public key. The input PSBT is never mutated.
    """
    validate(psbt)
    if not 0 <= index < len(psbt.inputs):
        raise PsbtFinalizeError("input index is out of range")
    inp = psbt.inputs[index]
    if _is_finalized(inp):
        raise PsbtFinalizeError("input is already finalized")

    try:
        amount, script_code, pubkey_hash = _input_signing_context(inp)
    except PsbtSignError as exc:
        raise PsbtFinalizeError(str(exc)) from exc
    pubkey, signature = _matching_partial_sig(inp, pubkey_hash)

    if len(signature) < 1 or signature[-1] not in _VALID_SIGHASH:
        raise PsbtFinalizeError("partial signature has an invalid sighash flag")
    if verify:
        r, s = _der_decode(signature[:-1])
        digest = bip143_sighash(_unsigned_tx(psbt), index, script_code, amount, signature[-1])
        try:
            point = secp256k1.decompress_pubkey(pubkey)
        except ValueError as exc:
            raise PsbtFinalizeError(f"partial signature public key is invalid: {exc}") from exc
        if not secp256k1.ecdsa_verify_digest(digest, (r, s), point):
            raise PsbtFinalizeError("partial signature does not verify against this input")

    final_witness = _final_scriptwitness(signature, pubkey)
    kept = [pair for pair in inp.pairs if pair.key_type not in _REDUNDANT_AFTER_FINALIZE]

    signed = Psbt(
        global_map=copy.deepcopy(psbt.global_map),
        inputs=[copy.deepcopy(m) for m in psbt.inputs],
        outputs=[copy.deepcopy(m) for m in psbt.outputs],
    )
    new_pairs = [copy.deepcopy(pair) for pair in kept]
    if _is_p2sh(inp):
        redeem_script = inp.get(PSBT_IN_REDEEM_SCRIPT)
        assert redeem_script is not None  # _is_p2sh guarantees it
        # scriptSig is a single data push of the redeemScript (P2SH-P2WPKH)
        new_pairs.append(KeyPair(bytes([PSBT_IN_FINAL_SCRIPTSIG]), ser_string(redeem_script)))
    new_pairs.append(KeyPair(bytes([PSBT_IN_FINAL_SCRIPTWITNESS]), final_witness))
    signed.inputs[index] = PsbtMap(new_pairs)
    validate(signed)  # finalized input must remain BIP-174 valid
    return signed


def _ready_to_finalize(inp: PsbtMap) -> bool:
    if _is_finalized(inp):
        return False
    try:
        _, _, pubkey_hash = _input_signing_context(inp)
        _matching_partial_sig(inp, pubkey_hash)
    except PsbtError:  # covers PsbtFinalizeError and the signer's PsbtSignError
        return False
    return True


def finalize(psbt: Psbt) -> Psbt:
    """Finalize every input that carries a matching partial signature, returning a new PSBT.

    Inputs that are already finalized, unsupported, or lacking a matching partial
    signature are left untouched. An input that is ready but carries a signature
    that does not verify raises :class:`PsbtFinalizeError`. The input is never mutated.
    """
    result = psbt
    for index, inp in enumerate(psbt.inputs):
        if _ready_to_finalize(inp):
            result = finalize_input(result, index)
    return result


def is_finalized(psbt: Psbt) -> bool:
    """Return whether every input of ``psbt`` has been finalized."""
    return len(psbt.inputs) > 0 and all(_is_finalized(inp) for inp in psbt.inputs)


__all__ = [
    "PsbtFinalizeError",
    "finalize",
    "finalize_input",
    "is_finalized",
]
