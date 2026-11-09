"""Opt-in live integration check against a known mainnet SegWit transaction."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from keylab.encoding.transaction import parse_transaction, serialize_transaction
from keylab.verify import ReadOnlyExplorerClient

_SEGWIT_TXID = "da917699942e4a96272401b534381a75512eeebe8403084500bd637bd47168b3"


@pytest.mark.live
def test_live_mempool_fetches_known_segwit_transaction() -> None:
    with ReadOnlyExplorerClient(timeout=15.0) as client:
        raw_transaction = client.get_transaction_hex(_SEGWIT_TXID)

    transaction = parse_transaction(raw_transaction)
    assert any(txin.witness for txin in transaction.inputs)
    stripped = replace(
        transaction,
        inputs=tuple(replace(txin, witness=()) for txin in transaction.inputs),
    )
    calculated_txid = hashlib.sha256(
        hashlib.sha256(serialize_transaction(stripped)).digest()
    ).digest()[::-1].hex()
    assert calculated_txid == _SEGWIT_TXID