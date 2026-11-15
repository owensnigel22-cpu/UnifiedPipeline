"""Resolve an address's public key from an on-chain spend, then bounded search.

A Bitcoin address is only a hash (a HASH160, or a script hash); the public key
behind it is **not** knowable from the address alone. It becomes known only once
the address *spends*, revealing the SEC public key in a witness (P2WPKH /
P2SH-P2WPKH) or scriptSig. :func:`resolve_pubkey_for_address` does exactly that --
it finds a spending input whose public key derives the queried address and returns
it -- and raises :class:`PubkeyNotRevealed` when no such spend exists, rather than
guessing.

:func:`recover_key_for_address` then feeds the resolved public key to Pollard's
kangaroo over a caller-supplied interval. **This is for bounded keys only** (puzzle
keys, weak-RNG keys): kangaroo costs ``~2*sqrt(hi - lo)`` group operations, so a
soundly generated 256-bit key -- whose interval is the whole group -- stays at
``~2**128`` hops and is untouched. It is not a general address cracker. Read-only
throughout: it fetches public data, never sweeps, signs, or broadcasts, and the
recovered scalar is masked unless explicitly revealed. See SECURITY.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from keylab.ec.secp256k1 import Point
from keylab.encoding.address import p2pkh_address, p2sh_p2wpkh_address, p2wpkh_address
from keylab.research.ecdlp.kangaroo import pollard_kangaroo
from keylab.research.forensics.nonce_scan import assemble_transaction
from keylab.research.forensics.signatures import extract_input_signatures
from keylab.verify.mainnet.client import ReadOnlyExplorerClient

__all__ = [
    "PubkeyNotRevealed",
    "ResolvedPubkey",
    "recover_key_for_address",
    "resolve_pubkey_for_address",
]


class PubkeyNotRevealed(Exception):
    """Raised when an address has not exposed its public key on-chain.

    The public key behind an address is unknown until the address *spends*. Until
    then it cannot be resolved -- and is never inferred from the address hash.
    """


@dataclass(frozen=True)
class ResolvedPubkey:
    """A public key recovered from a spending input, with the revealing location."""

    address: str
    pubkey: bytes
    public_point: Point
    txid: str
    input_index: int


def _derives_address(pubkey: bytes, address: str, network: str) -> bool:
    """True if ``address`` is any standard single-key form of ``pubkey``."""
    return address in (
        p2pkh_address(pubkey, network),
        p2wpkh_address(pubkey, network),
        p2sh_p2wpkh_address(pubkey, network),
    )


def resolve_pubkey_for_address(
    address: str,
    *,
    client: ReadOnlyExplorerClient,
    network: str = "mainnet",
    max_txs: int = 50,
) -> ResolvedPubkey:
    """Return the SEC public key an address exposed by spending (read-only).

    Scans the address's most recent ``max_txs`` transactions for a spending input
    whose witness public key derives ``address`` (P2WPKH / P2SH-P2WPKH / P2PKH form),
    and returns it with the revealing ``txid`` / ``input_index``. Raises
    :class:`PubkeyNotRevealed` if no such spend is found; the key is never inferred
    from the address hash. Fetches public data only and verifies nothing beyond the
    address derivation.
    """
    if client is None:
        raise RuntimeError("resolve_pubkey_for_address requires a ReadOnlyExplorerClient")
    if type(max_txs) is not int or max_txs < 1:
        raise ValueError("max_txs must be a positive integer")

    entries = client.get_address_transactions(address)[:max_txs]
    for entry in entries:
        parsed = assemble_transaction(client, entry)
        if parsed is None:
            continue
        txid, tx, spent_outputs = parsed
        for signature in extract_input_signatures(tx, spent_outputs, txid=txid):
            if _derives_address(signature.pubkey, address, network):
                return ResolvedPubkey(
                    address=address,
                    pubkey=signature.pubkey,
                    public_point=signature.public_point,
                    txid=signature.txid,
                    input_index=signature.input_index,
                )
    raise PubkeyNotRevealed(
        f"address {address!r} has not revealed a public key on-chain "
        "(no in-scope spending input found)"
    )


def recover_key_for_address(
    address: str,
    lo: int,
    hi: int,
    *,
    client: ReadOnlyExplorerClient,
    network: str = "mainnet",
    max_txs: int = 50,
    dp_bits: int | None = None,
    max_table_entries: int | None = None,
    max_steps: int | None = None,
    reveal_private: bool = False,
) -> dict[str, object]:
    """Resolve an address's public key, then run a bounded kangaroo search on ``[lo, hi]``.

    **Bounded intervals only.** Kangaroo recovers ``k`` in ``~2*sqrt(hi - lo)``
    group operations *only* when ``k`` is known to lie in a small interval (a puzzle
    key, a weak-RNG key). A soundly generated 256-bit key spans the whole group and
    stays at ``~2**128`` hops -- infeasible -- so this is **not** a general address
    cracker. The caller supplies ``[lo, hi]``; it is never assumed.

    Resolves the key via :func:`resolve_pubkey_for_address` (raising
    :class:`PubkeyNotRevealed` if the address never spent), then searches. The
    recovered scalar is withheld unless ``reveal_private=True``. Read-only; no
    sweeping, signing, or broadcasting.
    """
    resolved = resolve_pubkey_for_address(
        address, client=client, network=network, max_txs=max_txs
    )
    recovered = pollard_kangaroo(
        resolved.public_point,
        lo,
        hi,
        dp_bits=dp_bits,
        max_table_entries=max_table_entries,
        max_steps=max_steps,
    )
    found = recovered is not None
    return {
        "address": address,
        "pubkey": resolved.pubkey.hex(),
        "revealed_by": {"txid": resolved.txid, "input_index": resolved.input_index},
        "lo": lo,
        "hi": hi,
        "width": hi - lo,
        "found": found,
        "method": "pollard-kangaroo",
        "private_key_revealed": reveal_private,
        "private_key_hex": f"{recovered:064x}" if (found and reveal_private) else None,
    }
