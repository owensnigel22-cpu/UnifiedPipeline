"""Automated ECDSA nonce-reuse forensics over public Bitcoin transactions.

Pipeline: fetch an address's transactions (read-only, via the allow-listed
explorer client) -> extract each input's ``(z, r, s)`` -> group signatures by
``(public key, r)`` -> where one key signed two different digests with the same
``r`` (a reused nonce), call the existing recovery math and **forward-verify** the
result by re-deriving the public key before reporting it.

Scope and honesty boundary (see SECURITY.md):

- This recovers a key **only** from a signer who already leaked it by reusing a
  nonce on-chain. It does nothing against correct, unique-nonce ECDSA and breaks
  no primitive.
- SegWit v0 **P2WPKH / P2SH-P2WPKH** only (BIP-143). Legacy P2PKH is out of scope
  for now and such inputs are skipped, never guessed.
- Read-only: it fetches public data and derives/verifies addresses. It never
  sweeps, signs, or broadcasts, and the recovered scalar is withheld from
  serialized output unless ``reveal_private=True`` is passed explicitly.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from keylab.ec.sec1 import serialize_sec1
from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.encoding.address import (
    p2pkh_address,
    p2sh_p2wpkh_address,
    p2wpkh_address,
)
from keylab.encoding.transaction import Transaction, TxOut, parse_transaction
from keylab.research.ecdsa.nonce_reuse import recover_private_key_from_nonce_reuse
from keylab.research.forensics.signatures import (
    InputSignature,
    extract_input_signatures,
)
from keylab.verify.mainnet.client import ReadOnlyExplorerClient

__all__ = ["NonceReuseScanner", "NonceScanReport", "RecoveredKey"]

# (txid, parsed transaction, spent outputs in input order)
ParsedTransaction = tuple[str, Transaction, Sequence[TxOut]]


@dataclass(frozen=True)
class RecoveredKey:
    """A private key recovered from an on-chain nonce-reuse pair.

    ``verified`` is ``True`` only when ``private_key * G`` re-derives the exact
    witness public key, so a reported key is always a confirmed match.
    """

    private_key: int
    pubkey: bytes
    addresses: dict[str, str]
    evidence: tuple[InputSignature, InputSignature]
    verified: bool


@dataclass(frozen=True)
class NonceScanReport:
    """The outcome of scanning a set of transactions for nonce reuse."""

    address: str | None
    txids: tuple[str, ...]
    signatures_examined: int
    reused_r_groups: int
    low_s_count: int
    recovered: tuple[RecoveredKey, ...]

    @property
    def vulnerable(self) -> bool:
        return bool(self.recovered)

    def to_dict(self, *, reveal_private: bool = False) -> dict[str, object]:
        """A JSON-ready summary. The recovered scalar is masked unless requested."""
        return {
            "address": self.address,
            "txids": list(self.txids),
            "signatures_examined": self.signatures_examined,
            "reused_r_groups": self.reused_r_groups,
            "low_s_count": self.low_s_count,
            "vulnerable": self.vulnerable,
            "recovered": [
                _recovered_to_dict(key, reveal_private=reveal_private)
                for key in self.recovered
            ],
        }

    def to_json(self, *, reveal_private: bool = False, indent: int | None = None) -> str:
        return json.dumps(
            self.to_dict(reveal_private=reveal_private), indent=indent, sort_keys=True
        )


def _addresses(pubkey: bytes, network: str) -> dict[str, str]:
    return {
        "p2pkh": p2pkh_address(pubkey, network),
        "p2wpkh": p2wpkh_address(pubkey, network),
        "p2sh-p2wpkh": p2sh_p2wpkh_address(pubkey, network),
    }


def assemble_transaction(
    client: ReadOnlyExplorerClient, entry: dict
) -> ParsedTransaction | None:
    """Build ``(txid, Transaction, spent_outputs)`` from an explorer tx entry.

    Returns ``None`` for a coinbase input, a missing/malformed prevout, an
    unparsable raw transaction, or an input/output count mismatch. The spent
    outputs come from the explorer ``vin[].prevout`` in input order; the raw
    transaction bytes are fetched read-only via ``client``.
    """
    txid = entry.get("txid")
    vin = entry.get("vin")
    if not isinstance(txid, str) or not isinstance(vin, list):
        return None

    spent_outputs: list[TxOut] = []
    for vin_entry in vin:
        prevout = vin_entry.get("prevout") if isinstance(vin_entry, dict) else None
        if not isinstance(prevout, dict):
            return None  # coinbase or missing prevout -> skip the whole tx
        try:
            spent_outputs.append(
                TxOut(
                    amount=int(prevout["value"]),
                    script_pubkey=bytes.fromhex(prevout["scriptpubkey"]),
                )
            )
        except (KeyError, TypeError, ValueError):
            return None

    try:
        raw = client.get_transaction_hex(txid)
        tx = parse_transaction(raw)
    except (ValueError, TypeError):
        return None
    if len(tx.inputs) != len(spent_outputs):
        return None
    return txid, tx, spent_outputs


def _recovered_to_dict(key: RecoveredKey, *, reveal_private: bool) -> dict[str, object]:
    return {
        "verified": key.verified,
        "pubkey": key.pubkey.hex(),
        "addresses": key.addresses,
        "private_key_revealed": reveal_private,
        "private_key_hex": f"{key.private_key:064x}" if reveal_private else None,
        "evidence": [
            {
                "txid": item.txid,
                "input_index": item.input_index,
                "r": f"{item.r:064x}",
                "s": f"{item.s:064x}",
                "z": f"{item.z:064x}",
            }
            for item in key.evidence
        ],
    }


def _recover_from_group(
    group: Sequence[InputSignature], *, network: str
) -> RecoveredKey | None:
    """Try every pair in a ``(pubkey, r)`` group; return the first verified key."""
    for i in range(len(group)):
        for j in range(i + 1, len(group)):
            first, second = group[i], group[j]
            if first.z == second.z or (first.s - second.s) % N == 0:
                continue
            candidate = recover_private_key_from_nonce_reuse(
                first.r,
                first.s,
                first.z,
                second.s,
                second.z,
                public_key=first.public_point,
            )
            if candidate is None:
                continue
            # Forward verification: the scalar must re-derive the witness pubkey.
            if serialize_sec1(scalar_mult(candidate, G), compressed=True) != first.pubkey:
                continue
            return RecoveredKey(
                private_key=candidate,
                pubkey=first.pubkey,
                addresses=_addresses(first.pubkey, network),
                evidence=(first, second),
                verified=True,
            )
    return None


class NonceReuseScanner:
    """Scan transactions (or an address) for recoverable ECDSA nonce reuse."""

    def __init__(
        self, client: ReadOnlyExplorerClient | None = None, *, max_txs: int = 50
    ) -> None:
        if type(max_txs) is not int or max_txs < 1:
            raise ValueError("max_txs must be a positive integer")
        self._client = client
        self._max_txs = max_txs

    def scan_transactions(
        self,
        transactions: Iterable[ParsedTransaction],
        *,
        address: str | None = None,
        network: str = "mainnet",
    ) -> NonceScanReport:
        """Detect and recover nonce reuse in already-parsed transactions (offline).

        Each item is ``(txid, parsed_transaction, spent_outputs)``. This is the pure,
        network-free core that the fixtures exercise directly.
        """
        all_signatures: list[InputSignature] = []
        txids: list[str] = []
        for txid, tx, spent_outputs in transactions:
            txids.append(txid)
            all_signatures.extend(
                extract_input_signatures(tx, spent_outputs, txid=txid)
            )

        groups: dict[tuple[bytes, int], list[InputSignature]] = defaultdict(list)
        for signature in all_signatures:
            groups[(signature.pubkey, signature.r)].append(signature)

        recovered: list[RecoveredKey] = []
        seen_keys: set[int] = set()
        reused_groups = 0
        for group in groups.values():
            if len(group) < 2 or len({item.z for item in group}) < 2:
                continue
            reused_groups += 1
            key = _recover_from_group(group, network=network)
            if key is not None and key.private_key not in seen_keys:
                seen_keys.add(key.private_key)
                recovered.append(key)

        low_s_count = sum(1 for signature in all_signatures if signature.s > N // 2)
        return NonceScanReport(
            address=address,
            txids=tuple(txids),
            signatures_examined=len(all_signatures),
            reused_r_groups=reused_groups,
            low_s_count=low_s_count,
            recovered=tuple(recovered),
        )

    def scan_address(self, address: str, *, network: str = "mainnet") -> NonceScanReport:
        """Fetch an address's transactions and scan them for nonce reuse.

        Requires a :class:`ReadOnlyExplorerClient`. Only the newest ``max_txs``
        transactions are examined. Coinbase inputs and inputs whose prevout is
        unavailable are skipped.
        """
        if self._client is None:
            raise RuntimeError("scan_address requires a ReadOnlyExplorerClient")

        tx_entries = self._client.get_address_transactions(address)[: self._max_txs]
        transactions: list[ParsedTransaction] = []
        for entry in tx_entries:
            parsed = self._assemble_transaction(entry)
            if parsed is not None:
                transactions.append(parsed)
        return self.scan_transactions(transactions, address=address, network=network)

    def _assemble_transaction(self, entry: dict) -> ParsedTransaction | None:
        """Build ``(txid, Transaction, spent_outputs)`` from an explorer tx entry."""
        if self._client is None:  # pragma: no cover - guarded by scan_address
            return None
        return assemble_transaction(self._client, entry)
