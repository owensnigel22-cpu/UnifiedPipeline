"""BIP-174 Partially Signed Bitcoin Transaction (PSBT) parsing, validation, serialization.

This is a structural PSBT library for study and test-vector verification: it
parses, validates (BIP-174 rules), re-serializes PSBTs preserving unknown key
types, and implements the BIP-174 **Signer** and **Finalizer** roles for P2WPKH
and P2SH-P2WPKH inputs (deterministic ECDSA partial signatures, then final
scriptSig/scriptWitness construction), the **Extractor** role (final BIP-144
transaction from a finalized PSBT), and the **Combiner** role (union of PSBTs
sharing one unsigned transaction). It is **not** a wallet, and it does not
broadcast or merge differing transactions. See SECURITY.md.

Typical use::

    from keylab import psbt
    parsed = psbt.parse(raw_bytes)          # deserialize + validate
    assert psbt.serialize(parsed) == raw_bytes
    signed = psbt.sign(parsed, [private_scalar])   # add partial signatures
    combined = psbt.combine([signed_a, signed_b])  # union of signers' PSBTs
    final = psbt.finalize(combined)                # build scriptSig/scriptWitness
    tx = psbt.extract(final)                       # final network-serialized tx
"""

from __future__ import annotations

from keylab.psbt.combiner import PsbtCombineError, combine
from keylab.psbt.extractor import PsbtExtractError, extract, extract_transaction
from keylab.psbt.finalizer import PsbtFinalizeError, finalize, finalize_input, is_finalized
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
    "PsbtCombineError",
    "PsbtError",
    "PsbtExtractError",
    "PsbtFinalizeError",
    "PsbtMap",
    "PsbtSignError",
    "combine",
    "deserialize",
    "extract",
    "extract_transaction",
    "finalize",
    "finalize_input",
    "is_finalized",
    "parse",
    "serialize",
    "sign",
    "sign_input",
    "signable_inputs",
    "validate",
]
