"""BIP-174 Partially Signed Bitcoin Transaction (PSBT) parsing, validation, serialization.

This is a structural PSBT library for study and test-vector verification: it
parses, validates (BIP-174 rules), re-serializes PSBTs preserving unknown key
types, and implements the BIP-174 **Signer** role for P2WPKH and P2SH-P2WPKH
inputs (deterministic ECDSA partial signatures). It is **not** a wallet, and it
does not finalize, extract, combine, or broadcast. See SECURITY.md.

Typical use::

    from keylab import psbt
    parsed = psbt.parse(raw_bytes)          # deserialize + validate
    assert psbt.serialize(parsed) == raw_bytes
    signed = psbt.sign(parsed, [private_scalar])   # add partial signatures
"""

from __future__ import annotations

from keylab.psbt.model import (
    PSBT_MAGIC,
    KeyPair,
    Psbt,
    PsbtError,
    PsbtMap,
)
from keylab.psbt.parser import deserialize
from keylab.psbt.serializer import serialize
from keylab.psbt.signer import PsbtSignError, sign, sign_input, signable_inputs
from keylab.psbt.validator import validate


def parse(raw: bytes) -> Psbt:
    """Deserialize ``raw`` and apply the BIP-174 validation rules; raise :class:`PsbtError` on failure."""
    psbt = deserialize(raw)
    validate(psbt)
    return psbt


__all__ = [
    "PSBT_MAGIC",
    "KeyPair",
    "Psbt",
    "PsbtError",
    "PsbtMap",
    "PsbtSignError",
    "deserialize",
    "parse",
    "serialize",
    "sign",
    "sign_input",
    "signable_inputs",
    "validate",
]
