"""Tests for guarded test-network PSBT payment preparation and broadcast."""

from __future__ import annotations

import sys
import types
from decimal import Decimal
from typing import Any

import pytest

# ``keylab.verify`` eagerly imports the M7 HTTP client; keep these mocked-RPC
# tests runnable when the optional project dependency is absent locally.
try:
    import httpx  # noqa: F401
except ImportError:
    _httpx_stub = types.ModuleType("httpx")
    _httpx_stub.BaseTransport = object  # type: ignore[attr-defined]
    _httpx_stub.Client = object  # type: ignore[attr-defined]
    sys.modules["httpx"] = _httpx_stub

from keylab.encoding.address import hash160
from keylab.encoding.wif import encode
from keylab.verify.node import Network
from keylab.wallet.coinselect import CoinSelection
from keylab.wallet.tx import PaymentError, broadcast_prepared, prepare_payment
from keylab.wallet.utxo import UTXO

_PUBKEY = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
_SCRIPT = b"\x00\x14" + hash160(_PUBKEY)
_TXID = "12" * 32
_UTXO = UTXO(_TXID, 1, 100_000, _SCRIPT, f"wpkh({_PUBKEY.hex()})", 100, 68)
_SELECTION = CoinSelection((_UTXO,), 50_000, 100_000, 1_000, 49_000, 141, 0, 4, True)
_UNSET = object()


class _Keys:
    def get_wif(self, alias: str) -> str:
        assert alias == "test-key"
        return encode(1, compressed=True, network="testnet")


class _RPC:
    def __init__(self, *, allowed: bool = True, output: Any = _UNSET) -> None:
        self.allowed = allowed
        self.output = (
            {"value": Decimal("0.00100000"), "scriptPubKey": {"hex": _SCRIPT.hex()}}
            if output is _UNSET
            else output
        )
        self.methods: list[str] = []
        self.sent: list[tuple[str, Network, bool]] = []

    def getblockchaininfo(self) -> dict[str, Any]:
        self.methods.append("getblockchaininfo")
        return {"chain": "regtest"}

    def gettxout(self, txid: str, vout: int, *, include_mempool: bool = True) -> dict[str, Any] | None:
        self.methods.append("gettxout")
        assert (txid, vout, include_mempool) == (_TXID, 1, True)
        return self.output

    def testmempoolaccept(self, transactions: list[str]) -> list[dict[str, Any]]:
        self.methods.append("testmempoolaccept")
        assert len(transactions) == 1
        return [{"allowed": self.allowed, "reject-reason": "test rejection"}]

    def sendrawtransaction(
        self, raw_tx: str, *, network: Network, confirm_test_network: bool
    ) -> str:
        self.methods.append("sendrawtransaction")
        self.sent.append((raw_tx, network, confirm_test_network))
        from keylab.wallet.tx import _transaction_id

        return _transaction_id(bytes.fromhex(raw_tx))


def _prepare(client: _RPC):
    return prepare_payment(
        client,
        Network.REGTEST,
        _SELECTION,
        destination_script_pubkey=b"\x00\x14" + b"\x33" * 20,
        change_script_pubkey=_SCRIPT,
        key_alias="test-key",
        key_provider=_Keys(),
    )


def test_prepare_payment_signs_finalizes_and_preflights_without_broadcast() -> None:
    client = _RPC()
    prepared = _prepare(client)
    assert prepared.network is Network.REGTEST
    assert prepared.fee_sats == 1_000
    assert prepared.raw_transaction
    assert prepared.txid
    assert client.methods == ["getblockchaininfo", "gettxout", "testmempoolaccept"]
    assert client.sent == []


def test_broadcast_prepared_rechecks_and_sends_once_after_preflight() -> None:
    client = _RPC()
    prepared = _prepare(client)
    client.methods.clear()
    txid = broadcast_prepared(
        client, prepared, network=Network.REGTEST, confirm_test_network=True
    )
    assert txid == prepared.txid
    assert [method for method in client.methods if method == "sendrawtransaction"] == [
        "sendrawtransaction"
    ]
    assert len(client.sent) == 1
    assert client.sent[0][1:] == (Network.REGTEST, True)
    assert client.methods.index("testmempoolaccept") < client.methods.index("sendrawtransaction")


@pytest.mark.parametrize("operation", ["prepare", "broadcast"])
def test_mainnet_is_rejected_before_rpc_activity(operation: str) -> None:
    client = _RPC()
    prepared = _prepare(_RPC())
    with pytest.raises(RuntimeError, match="mainnet"):
        if operation == "prepare":
            prepare_payment(
                client,
                Network.MAINNET,
                _SELECTION,
                destination_script_pubkey=_SCRIPT,
                change_script_pubkey=_SCRIPT,
                key_alias="test-key",
                key_provider=_Keys(),
            )
        else:
            broadcast_prepared(
                client, prepared, network=Network.MAINNET, confirm_test_network=True
            )
    assert client.methods == []
    assert client.sent == []


def test_broadcast_requires_explicit_confirmation_before_rpc_activity() -> None:
    client = _RPC()
    prepared = _prepare(_RPC())
    with pytest.raises(RuntimeError, match="explicit test-network confirmation"):
        broadcast_prepared(
            client, prepared, network=Network.REGTEST, confirm_test_network=False
        )
    assert client.methods == []


def test_prepare_refuses_missing_or_changed_selected_outputs() -> None:
    for output in (None, {"value": Decimal("0.0009"), "scriptPubKey": {"hex": _SCRIPT.hex()}}):
        client = _RPC(output=output)
        with pytest.raises(PaymentError, match="no longer unspent|changed"):
            _prepare(client)
        assert "testmempoolaccept" not in client.methods


def test_prepare_refuses_node_preflight_rejection() -> None:
    client = _RPC(allowed=False)
    with pytest.raises(PaymentError, match="rejected transaction"):
        _prepare(client)
    assert client.sent == []


def test_broadcast_refuses_node_preflight_rejection() -> None:
    prepared = _prepare(_RPC())
    client = _RPC(allowed=False)
    with pytest.raises(PaymentError, match="rejected transaction"):
        broadcast_prepared(
            client, prepared, network=Network.REGTEST, confirm_test_network=True
        )
    assert client.sent == []
    assert "sendrawtransaction" not in client.methods


def test_broadcast_refuses_network_mismatch() -> None:
    prepared = _prepare(_RPC())
    client = _RPC()
    with pytest.raises(PaymentError, match="network does not match"):
        broadcast_prepared(
            client, prepared, network=Network.TESTNET, confirm_test_network=True
        )
    assert client.methods == []
