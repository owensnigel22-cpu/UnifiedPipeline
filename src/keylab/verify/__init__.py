"""Local verification of Bitcoin transactions, optionally against read-only mainnet data.

The explorer is an untrusted data source: it hands over bytes, and every
cryptographic judgement (signatures, proof-of-work, txid/merkle matching) is made
locally by keylab.ec.* / keylab.encoding.* primitives. No signing, no
broadcasting, no keys transmitted. See SECURITY.md and docs/verify_mainnet.md.
"""

from __future__ import annotations

from keylab.verify.mainnet import (
	DEFAULT_ALLOWLIST,
	ReadOnlyExplorerClient,
	verify_p2wpkh_input,
	verify_transaction_signatures,
	verify_transactions_signatures_batch,
)

__all__ = [
	"DEFAULT_ALLOWLIST",
	"ReadOnlyExplorerClient",
	"verify_p2wpkh_input",
	"verify_transaction_signatures",
	"verify_transactions_signatures_batch",
]
