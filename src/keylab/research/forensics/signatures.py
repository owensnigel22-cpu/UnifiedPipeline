"""Extract ECDSA ``(z, r, s)`` material from fetched Bitcoin transactions.

Role: turn a parsed transaction plus its spent outputs into the per-input
signature facts that nonce-reuse forensics needs -- the signed BIP-143 digest
``z`` (as an integer), the decoded signature ``(r, s)``, and the public key.

Scope: SegWit v0 **P2WPKH** and **P2SH-P2WPKH** only (BIP-143), reusing
:func:`keylab.verify.mainnet.verification.prepare_witness_signature`. Legacy
pre-SegWit P2PKH sighash reconstruction is **out of scope** for now (there is no
legacy sighash in the encoding layer yet); such inputs are skipped, not guessed.
This module verifies nothing and recovers nothing; it only reports facts.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from keylab.ec.secp256k1 import Point
from keylab.encoding.transaction import Transaction, TxOut
from keylab.verify.mainnet.verification import prepare_witness_signature

__all__ = ["InputSignature", "extract_input_signatures", "script_type_of"]

_P2WPKH_PREFIX = b"\x00\x14"
_P2SH_PREFIX = b"\xa9\x14"
_P2SH_SUFFIX = b"\x87"


def script_type_of(script_pubkey: bytes) -> str | None:
    """Classify a spent output's ``scriptPubKey`` as a supported input type.

    Returns ``"p2wpkh"`` or ``"p2sh-p2wpkh"`` for the two in-scope SegWit v0 forms,
    or ``None`` for anything else (including legacy P2PKH, which is out of scope).
    """
    if len(script_pubkey) == 22 and script_pubkey[:2] == _P2WPKH_PREFIX:
        return "p2wpkh"
    if (
        len(script_pubkey) == 23
        and script_pubkey[:2] == _P2SH_PREFIX
        and script_pubkey[-1:] == _P2SH_SUFFIX
    ):
        return "p2sh-p2wpkh"
    return None


@dataclass(frozen=True)
class InputSignature:
    """One input's signed digest and decoded ECDSA signature.

    ``z`` is the BIP-143 sighash as an integer (the value actually signed). ``r`` and
    ``s`` are the decoded DER signature components. ``pubkey`` is the 33-byte
    compressed SEC public key from the witness; ``public_point`` is the same key as an
    ``(x, y)`` curve point.
    """

    txid: str
    input_index: int
    z: int
    r: int
    s: int
    pubkey: bytes
    public_point: Point
    script_type: str


def extract_input_signatures(
    tx: Transaction, spent_outputs: Sequence[TxOut], *, txid: str
) -> list[InputSignature]:
    """Return an :class:`InputSignature` for each in-scope, well-formed input.

    ``spent_outputs`` must be in transaction input order (one per input), as returned
    by an explorer's ``vin[].prevout``. Inputs outside the P2WPKH / P2SH-P2WPKH scope,
    coinbase inputs, and malformed witnesses are skipped. No signature is verified.
    """
    if len(spent_outputs) != len(tx.inputs):
        raise ValueError("exactly one spent output is required for every transaction input")

    signatures: list[InputSignature] = []
    for index, spent_output in enumerate(spent_outputs):
        script_type = script_type_of(spent_output.script_pubkey)
        if script_type is None:
            continue
        prepared = prepare_witness_signature(tx, index, spent_output)
        if prepared is None:
            continue
        digest, (r, s), point = prepared
        pubkey = tx.inputs[index].witness[1]
        signatures.append(
            InputSignature(
                txid=txid,
                input_index=index,
                z=int.from_bytes(digest, "big"),
                r=r,
                s=s,
                pubkey=pubkey,
                public_point=point,
                script_type=script_type,
            )
        )
    return signatures
