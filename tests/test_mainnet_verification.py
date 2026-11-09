"""Mocked explorer fetch plus local BIP-143 signature verification."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx

from keylab.encoding.transaction import TxOut, parse_transaction, serialize_transaction
from keylab.verify import (
    ReadOnlyExplorerClient,
    verify_transaction_signatures,
    verify_transactions_signatures_batch,
)

_VECTOR_PATH = Path(__file__).parent / "vectors" / "bip143_signing_vectors.json"
_CASES = json.loads(_VECTOR_PATH.read_text(encoding="utf-8"))["cases"]
_VECTOR = next(case for case in _CASES if case["name"] == "bip143-p2sh-p2wpkh")
_TXID = "ab" * 32


def _spent_output() -> TxOut:
    return TxOut(
        amount=_VECTOR["amount"],
        script_pubkey=bytes.fromhex(_VECTOR["scriptpubkey"]),
    )


def test_mocked_fetch_parse_and_verify_known_bip143_transaction() -> None:
    requests: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append((request.method, request.url.path))
        if request.url.path == f"/api/tx/{_TXID}/hex":
            return httpx.Response(200, text=_VECTOR["final_tx"])
        if request.url.path == f"/api/tx/{_TXID}/merkle-proof":
            return httpx.Response(
                200,
                json={"block_height": 1, "pos": 0, "merkle": []},
            )
        return httpx.Response(404)

    with ReadOnlyExplorerClient(transport=httpx.MockTransport(handler)) as client:
        raw_transaction = client.get_transaction_hex(_TXID)
        merkle_proof: dict[str, Any] = client.get_merkle_proof(_TXID)

    parsed = parse_transaction(raw_transaction)
    assert len(parsed.inputs) == 1
    assert merkle_proof == {"block_height": 1, "pos": 0, "merkle": []}
    assert verify_transaction_signatures(raw_transaction, (_spent_output(),)) is True
    assert verify_transactions_signatures_batch(
        ((raw_transaction, (_spent_output(),)),), backend="python"
    ) is True
    assert requests == [
        ("GET", f"/api/tx/{_TXID}/hex"),
        ("GET", f"/api/tx/{_TXID}/merkle-proof"),
    ]


def test_tampered_bip143_witness_signature_fails_verification() -> None:
    raw_transaction = bytes.fromhex(_VECTOR["final_tx"])
    parsed = parse_transaction(raw_transaction)
    witness_signature, public_key = parsed.inputs[0].witness
    tampered_signature = bytearray(witness_signature)
    tampered_signature[4] ^= 0x01
    tampered_input = replace(
        parsed.inputs[0],
        witness=(bytes(tampered_signature), public_key),
    )
    tampered_transaction = replace(parsed, inputs=(tampered_input,))

    assert not verify_transaction_signatures(
        serialize_transaction(tampered_transaction),
        (_spent_output(),),
    )
    assert not verify_transactions_signatures_batch(
        ((serialize_transaction(tampered_transaction), (_spent_output(),)),),
        backend="python",
    )
