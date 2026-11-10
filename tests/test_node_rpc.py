"""Unit tests for the Bitcoin Core JSON-RPC transport."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Any, ClassVar

import pytest

# ``keylab.verify`` eagerly imports the M7 HTTP client. Keep this focused unit
# test runnable in a source checkout that has not installed project deps.
try:
    import httpx  # noqa: F401
except ImportError:
    _httpx_stub = types.ModuleType("httpx")
    _httpx_stub.BaseTransport = object  # type: ignore[attr-defined]
    _httpx_stub.Client = object  # type: ignore[attr-defined]
    sys.modules["httpx"] = _httpx_stub

from keylab.verify.node import BitcoinRPCClient, BitcoinRPCError, Network


class _FakeResponse:
    def __init__(self, payload: Any, status_code: int = 200) -> None:
        self._payload = payload
        self.text = payload if isinstance(payload, str) else json.dumps(payload)
        self.status_code = status_code
        self.is_error = status_code >= 400

    def json(self) -> Any:
        if isinstance(self._payload, BaseException):
            raise self._payload
        return self._payload


class _FakeClient:
    instances: ClassVar[list[_FakeClient]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.options = kwargs
        self.calls: list[dict[str, Any]] = []
        self.results: list[tuple[Any, int] | BaseException] = []
        self.closed = False
        self.__class__.instances.append(self)

    def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append({"url": url, **kwargs})
        if not self.results:
            request = json.loads(kwargs["content"])
            return _FakeResponse({"result": None, "error": None, "id": request["id"]})
        configured = self.results.pop(0)
        if isinstance(configured, BaseException):
            raise configured
        body, status = configured
        return _FakeResponse(body, status)

    def close(self) -> None:
        self.closed = True


class _FakeHTTPError(Exception):
    pass


@pytest.fixture
def fake_httpx(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    _FakeClient.instances.clear()
    module = types.ModuleType("httpx")
    module.Client = _FakeClient  # type: ignore[attr-defined]
    module.HTTPError = _FakeHTTPError  # type: ignore[attr-defined]
    module.Timeout = lambda value: ("timeout", value)  # type: ignore[attr-defined]
    module.Limits = lambda **kwargs: ("limits", kwargs)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "httpx", module)
    return module


def test_rpc_uses_pooled_client_and_validates_chain_response(fake_httpx: types.ModuleType) -> None:
    del fake_httpx
    client = BitcoinRPCClient()
    fake = _FakeClient.instances[-1]
    assert fake.options["follow_redirects"] is False
    assert fake.options["trust_env"] is False
    assert fake.options["limits"] == ("limits", {"max_connections": 4, "max_keepalive_connections": 4})
    fake.results.append(
        ({"result": {"chain": "regtest", "blocks": 10}, "error": None, "id": 1}, 200)
    )

    result = client.getblockchaininfo()

    assert result == {"chain": "regtest", "blocks": 10}
    request = json.loads(fake.calls[0]["content"])
    assert request == {"jsonrpc": "1.0", "id": 1, "method": "getblockchaininfo", "params": []}
    client.close()
    assert fake.closed


def test_rpc_supports_basic_auth_and_cookie_auth(
    fake_httpx: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del fake_httpx
    basic = BitcoinRPCClient(rpc_user="rpc-user", rpc_password="rpc-secret")
    basic.call("getblockchaininfo")
    assert _FakeClient.instances[-1].calls[0]["auth"] == ("rpc-user", "rpc-secret")

    monkeypatch.setattr(Path, "read_text", lambda self, **kwargs: "cookie-user:cookie-secret")
    cookie = BitcoinRPCClient(cookie_file="/mock/.cookie")
    cookie.call("getblockchaininfo")
    assert _FakeClient.instances[-1].calls[0]["auth"] == ("cookie-user", "cookie-secret")


def test_rpc_warns_for_remote_plain_http(fake_httpx: types.ModuleType) -> None:
    del fake_httpx
    with pytest.warns(RuntimeWarning, match="unencrypted"):
        client = BitcoinRPCClient("http://node.example:8332/")
    client.close()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"url": "ftp://127.0.0.1:8332"},
        {"url": "http://user:pass@localhost:8332"},
        {"url": "http://localhost:8332/?token=secret"},
        {"rpc_user": "user"},
        {"cookie_file": "/mock/.cookie", "rpc_user": "user", "rpc_password": "pass"},
        {"timeout": 0},
        {"max_connections": 0},
    ],
)
def test_rpc_rejects_invalid_configuration(
    fake_httpx: types.ModuleType,
    kwargs: dict[str, Any],
) -> None:
    del fake_httpx
    with pytest.raises(ValueError):
        BitcoinRPCClient(**kwargs)


def test_rpc_errors_are_structured_and_transport_failures_are_sanitized(
    fake_httpx: types.ModuleType,
) -> None:
    del fake_httpx
    client = BitcoinRPCClient()
    fake = _FakeClient.instances[-1]
    fake.results.append(
        ({"result": None, "error": {"code": -5, "message": "No such transaction"}, "id": 1}, 500)
    )
    with pytest.raises(BitcoinRPCError, match="No such transaction") as rpc_error:
        client.call("getrawtransaction", ("00" * 32,))
    assert rpc_error.value.code == -5

    fake.results.append(_FakeHTTPError("authorization: rpc-secret"))
    with pytest.raises(BitcoinRPCError, match="HTTP transport failed") as transport_error:
        client.call("getblockchaininfo")
    assert "rpc-secret" not in str(transport_error.value)
    client.close()


def test_rpc_does_not_retry_sendrawtransaction_after_transport_error(
    fake_httpx: types.ModuleType,
) -> None:
    del fake_httpx
    client = BitcoinRPCClient()
    fake = _FakeClient.instances[-1]
    fake.results.append(
        ({"result": {"chain": "regtest", "blocks": 1}, "error": None, "id": 1}, 200)
    )
    fake.results.append(_FakeHTTPError("connection reset"))
    with pytest.raises(BitcoinRPCError):
        client.sendrawtransaction("00", network=Network.REGTEST, confirm_test_network=True)
    assert len(fake.calls) == 2
    assert json.loads(fake.calls[1]["content"])["method"] == "sendrawtransaction"
    client.close()


def test_rpc_validates_outpoints_and_transaction_hex(fake_httpx: types.ModuleType) -> None:
    del fake_httpx
    client = BitcoinRPCClient()
    with pytest.raises(ValueError, match="txid"):
        client.gettxout("bad", 0)
    with pytest.raises(ValueError, match="vout"):
        client.gettxout("00" * 32, -1)
    with pytest.raises(ValueError, match="hexadecimal"):
        client.sendrawtransaction(
            "zz", network=Network.REGTEST, confirm_test_network=True
        )
    client.close()


def test_rpc_wrappers_use_expected_core_methods_and_parameters(
    fake_httpx: types.ModuleType,
) -> None:
    del fake_httpx
    client = BitcoinRPCClient()
    fake = _FakeClient.instances[-1]
    fake.results.extend(
        [
            ({"result": {"value": 1.25}, "error": None, "id": 1}, 200),
            ({"result": "00", "error": None, "id": 2}, 200),
            ({"result": [{"allowed": True}], "error": None, "id": 3}, 200),
            ({"result": {"chain": "regtest", "blocks": 1}, "error": None, "id": 4}, 200),
            ({"result": "ab" * 32, "error": None, "id": 5}, 200),
        ]
    )

    txid = "01" * 32
    assert client.gettxout(txid, 2) == {"value": 1.25}
    assert client.getrawtransaction(txid) == "00"
    assert client.testmempoolaccept(["00"]) == [{"allowed": True}]
    assert client.sendrawtransaction(
        "00", network=Network.REGTEST, confirm_test_network=True
    ) == "ab" * 32
    requests = [json.loads(call["content"]) for call in fake.calls]
    assert [request["method"] for request in requests] == [
        "gettxout",
        "getrawtransaction",
        "testmempoolaccept",
        "getblockchaininfo",
        "sendrawtransaction",
    ]
    assert requests[0]["params"] == [txid, 2, True]
    assert requests[2]["params"] == [["00"]]
    client.close()


def test_rpc_broadcast_guard_rejects_mainnet_and_unconfirmed_calls_before_network_io(
    fake_httpx: types.ModuleType,
) -> None:
    del fake_httpx
    client = BitcoinRPCClient()
    fake = _FakeClient.instances[-1]
    with pytest.raises(RuntimeError, match="mainnet broadcasting is disabled"):
        client.sendrawtransaction("00", network=Network.MAINNET, confirm_test_network=True)
    with pytest.raises(RuntimeError, match="explicit test-network confirmation"):
        client.sendrawtransaction("00", network=Network.REGTEST, confirm_test_network=False)
    with pytest.raises(RuntimeError, match="guarded broadcast"):
        client.call("sendrawtransaction", ("00",))
    assert fake.calls == []
    client.close()


@pytest.mark.parametrize(
    ("network", "chain"),
    [(Network.TESTNET, "test"), (Network.REGTEST, "regtest")],
)
def test_rpc_broadcast_guard_checks_node_chain(
    fake_httpx: types.ModuleType,
    network: Network,
    chain: str,
) -> None:
    del fake_httpx
    client = BitcoinRPCClient()
    fake = _FakeClient.instances[-1]
    fake.results.append(({"result": {"chain": chain, "blocks": 3}, "error": None, "id": 1}, 200))
    fake.results.append(({"result": "ab" * 32, "error": None, "id": 2}, 200))
    assert client.sendrawtransaction("00", network=network, confirm_test_network=True) == "ab" * 32
    assert [json.loads(call["content"])["method"] for call in fake.calls] == [
        "getblockchaininfo",
        "sendrawtransaction",
    ]
    client.close()
