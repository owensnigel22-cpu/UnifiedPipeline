"""Mocked end-to-end regtest wallet integration (no live node required)."""

from __future__ import annotations

import sys
import types
from decimal import Decimal
from typing import Any

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
from keylab.wallet.coinselect import select_coins_bnb
from keylab.wallet.tx import broadcast_prepared, prepare_payment
from keylab.wallet.utxo import scan_utxos

_PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
_SCRIPT = b"\x00\x14" + hash160(bytes.fromhex(_PUBKEY))
_TIP = "ab" * 32
_TXID = "cd" * 32


class _TestKeyring:
    def get_wif(self, alias: str) -> str:
        assert alias == "regtest-fixture"
        return encode(1, compressed=True, network="testnet")


class _MockCoreRPC:
    """RPC-shaped fixture that records calls and simulates a regtest node."""

    def __init__(self) -> None:
        self.methods: list[str] = []
        self.broadcasts: list[str] = []

    def getblockchaininfo(self) -> dict[str, Any]:
        self.methods.append("getblockchaininfo")
        return {"chain": "regtest", "blocks": 1, "bestblockhash": _TIP}

    def scantxoutset(self, objects: list[str | dict[str, Any]]) -> dict[str, Any]:
        self.methods.append("scantxoutset")
        assert objects == [f"wpkh({_PUBKEY})"]
        return {
            "success": True,
            "bestblock": _TIP,
            "height": 1,
            "txouts": 1,
            "unspents": [
                {
                    "txid": _TXID,
                    "vout": 0,
                    "scriptPubKey": _SCRIPT.hex(),
                    "desc": f"wpkh({_PUBKEY})",
                    "amount": Decimal("0.00100000"),
                    "height": 1,
                }
            ],
        }

    def gettxout(self, txid: str, vout: int, *, include_mempool: bool = True) -> dict[str, Any]:
        self.methods.append("gettxout")
        assert (txid, vout, include_mempool) == (_TXID, 0, True)
        return {"value": Decimal("0.00100000"), "scriptPubKey": {"hex": _SCRIPT.hex()}}

    def testmempoolaccept(self, transactions: list[str]) -> list[dict[str, Any]]:
        self.methods.append("testmempoolaccept")
        assert len(transactions) == 1
        return [{"allowed": True}]

    def sendrawtransaction(
        self, raw_tx: str, *, network: Network, confirm_test_network: bool
    ) -> str:
        self.methods.append("sendrawtransaction")
        if network is Network.MAINNET or not confirm_test_network:
            raise RuntimeError("test-network broadcast guard rejected request")
        self.broadcasts.append(raw_tx)
        from keylab.wallet.tx import _transaction_id

        return _transaction_id(bytes.fromhex(raw_tx))


def test_mocked_regtest_scan_select_prepare_and_guarded_broadcast() -> None:
    rpc = _MockCoreRPC()
    scan = scan_utxos(rpc, f"wpkh({_PUBKEY})")
    selection = select_coins_bnb(
        scan.utxos,
        50_000,
        fee_rate_sat_vb=1,
        destination_script_pubkey=b"\x00\x14" + b"\x44" * 20,
        change_script_pubkey=_SCRIPT,
        max_fee_sats=1_000,
    )
    prepared = prepare_payment(
        rpc,
        Network.REGTEST,
        selection,
        destination_script_pubkey=b"\x00\x14" + b"\x44" * 20,
        change_script_pubkey=_SCRIPT,
        key_alias="regtest-fixture",
        key_provider=_TestKeyring(),
    )
    assert not rpc.broadcasts
    result = broadcast_prepared(
        rpc, prepared, network=Network.REGTEST, confirm_test_network=True
    )
    assert result == prepared.txid
    assert len(rpc.broadcasts) == 1
    assert rpc.methods.index("testmempoolaccept") < rpc.methods.index("sendrawtransaction")
    assert rpc.methods.count("sendrawtransaction") == 1
