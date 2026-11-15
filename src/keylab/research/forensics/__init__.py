"""Educational Bitcoin forensics over public on-chain data.

Recovers keys **only** from already-broken constructions (so far: ECDSA
nonce reuse a signer leaked on-chain), on read-only public data, with every
recovered key forward-verified. It breaks no primitive and gives no advantage
against soundly generated keys. See SECURITY.md.
"""

from keylab.research.forensics.address_search import (
    PubkeyNotRevealed,
    ResolvedPubkey,
    recover_key_for_address,
    resolve_pubkey_for_address,
)
from keylab.research.forensics.nonce_scan import (
    NonceReuseScanner,
    NonceScanReport,
    RecoveredKey,
)
from keylab.research.forensics.signatures import (
    InputSignature,
    extract_input_signatures,
    script_type_of,
)

__all__ = [
    "InputSignature",
    "NonceReuseScanner",
    "NonceScanReport",
    "PubkeyNotRevealed",
    "RecoveredKey",
    "ResolvedPubkey",
    "extract_input_signatures",
    "recover_key_for_address",
    "resolve_pubkey_for_address",
    "script_type_of",
]
