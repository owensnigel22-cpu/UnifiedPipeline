"""HTTP API broadcasters (mocked httpx — no real network).

Broadcasting pushes an ALREADY-SIGNED raw transaction; these tests inject a
MockTransport, assert the correct POST is made, the txid is returned, and that a
400 ("already in mempool") is surfaced as a BroadcastError with already_known set.
"""

from __future__ import annotations

import httpx
import pytest

from keylab.verify.node import Network
from keylab.wallet.broadcast_api import (
    BlockCypherBroadcaster,
    BroadcastError,
    MempoolSpaceBroadcaster,
)

_RAW = "02000000000101abcdef00" * 4  # plausible signed-tx hex (content irrelevant to the mock)
_TXID = "ab" * 32


def test_mempool_space_posts_and_returns_txid() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["url"] = str(request.url)
        seen["body"] = request.content.decode()
        return httpx.Response(200, text=_TXID)

    with MempoolSpaceBroadcaster(Network.MAINNET, transport=httpx.MockTransport(handler)) as caster:
        assert caster.broadcast(_RAW) == _TXID
    assert seen["method"] == "POST"
    assert seen["url"] == "https://mempool.space/api/tx"
    assert seen["body"] == _RAW


def test_mempool_space_testnet_base() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith("https://mempool.space/testnet/api/tx")
        return httpx.Response(200, text=_TXID)

    with MempoolSpaceBroadcaster(Network.TESTNET, transport=httpx.MockTransport(handler)) as caster:
        assert caster.broadcast(_RAW) == _TXID


def test_mempool_space_400_already_in_mempool() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="Transaction already in mempool")

    with MempoolSpaceBroadcaster(transport=httpx.MockTransport(handler)) as caster,             pytest.raises(BroadcastError) as exc:
        caster.broadcast(_RAW)
    assert exc.value.status == 400 and exc.value.already_known is True


def test_blockcypher_posts_json_and_returns_hash() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        seen["url"] = str(request.url)
        seen["json"] = json.loads(request.content)
        return httpx.Response(201, json={"tx": {"hash": _TXID}})

    with BlockCypherBroadcaster(Network.MAINNET, transport=httpx.MockTransport(handler)) as caster:
        assert caster.broadcast(_RAW) == _TXID
    assert seen["url"].startswith("https://api.blockcypher.com/v1/btc/main/txs/push")
    assert seen["json"] == {"tx": _RAW}


def test_blockcypher_error_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="error: invalid tx")

    with BlockCypherBroadcaster(transport=httpx.MockTransport(handler)) as caster,             pytest.raises(BroadcastError, match="BlockCypher rejected"):
        caster.broadcast(_RAW)


def test_rejects_non_https_and_bad_hex() -> None:
    with pytest.raises(ValueError, match="https"):
        MempoolSpaceBroadcaster(base="http://mempool.space")
    with MempoolSpaceBroadcaster(transport=httpx.MockTransport(lambda r: httpx.Response(200, text=""))) as caster,             pytest.raises(ValueError, match="hex"):
        caster.broadcast("nothex!!")
    with pytest.raises(ValueError, match="regtest|endpoint"):
        MempoolSpaceBroadcaster(Network.REGTEST)
