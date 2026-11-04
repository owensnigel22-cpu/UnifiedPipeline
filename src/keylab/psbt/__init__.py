"""BIP-174 Partially Signed Bitcoin Transaction (PSBT) parsing, validation, serialization.

This is a structural PSBT library for study and test-vector verification: it
parses, validates (BIP-174 rules), and re-serializes PSBTs, preserving unknown
key types for forward compatibility. It is **not** a wallet, signer, finalizer,
extractor, or transaction broadcaster, and performs no signing. See SECURITY.md.

Typical use::

    from keylab import psbt
    parsed = psbt.parse(raw_bytes)          # deserialize + validate
    assert psbt.serialize(parsed) == raw_bytes
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
    "deserialize",
    "parse",
    "serialize",
    "validate",
]
