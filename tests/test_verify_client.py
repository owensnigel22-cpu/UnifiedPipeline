"""Read-only explorer client: TLS/HTTPS/allow-list guards + AST read-only boundary.

The hard read-only boundary is checked STRUCTURALLY with the `ast` module (not
string matching, which false-positives on comments/logs): the client's source
must contain no POST/PUT/PATCH/DELETE HTTP call, no `verify=False`, and no import
from a signing/broadcasting module.
"""

from __future__ import annotations

import ast
import ssl
from pathlib import Path

import httpx
import pytest

from keylab.verify import DEFAULT_ALLOWLIST, ReadOnlyExplorerClient

_CLIENT_SRC = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "keylab"
    / "verify"
    / "mainnet"
    / "client.py"
)


def _mock_client(handler) -> ReadOnlyExplorerClient:
    return ReadOnlyExplorerClient(transport=httpx.MockTransport(handler))


# --- transport / fetch behaviour (mocked, no real sockets) --------------------------------------

def test_get_transaction_uses_https_get_and_parses_json() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"txid": "ab" * 32, "vin": []})

    with _mock_client(handler) as client:
        data = client.get_transaction("ab" * 32)
    assert seen["method"] == "GET"
    assert seen["url"] == "https://mempool.space/api/tx/" + "ab" * 32
    assert data["txid"] == "ab" * 32


def test_block_header_returns_bytes() -> None:
    header_hex = "00" * 80

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=header_hex)

    with _mock_client(handler) as client:
        assert client.get_block_header("cd" * 32) == bytes(80)


# --- TLS / HTTPS / allow-list enforcement -------------------------------------------------------

def test_rejects_non_https_base() -> None:
    with pytest.raises(ValueError, match="https"):
        ReadOnlyExplorerClient(allowlist=("http://mempool.space",))


def test_rejects_off_allowlist_host() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # should never be called
        raise AssertionError("request must be blocked before transport")

    with _mock_client(handler) as client, pytest.raises(ValueError, match="allow-list"):
        client.get_transaction("ab" * 32, base="https://evil.example.com")


def test_tls_context_is_1_2_plus_and_validating() -> None:
    from keylab.verify.mainnet.client import _tls_context
    ctx = _tls_context()
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_invalid_txid_rejected_before_network() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must be rejected before transport")

    with _mock_client(handler) as client, pytest.raises(ValueError, match="hex"):
        client.get_transaction("not-a-valid-txid")


# --- AST read-only boundary (structural, not string matching) -----------------------------------

def _client_tree() -> ast.Module:
    tree = ast.parse(_CLIENT_SRC.read_text(encoding="utf-8"))
    return tree


def test_client_uses_only_get_for_http_methods() -> None:
    tree = _client_tree()
    http_methods = {
        "get", "post", "put", "patch", "delete", "head", "options", "request", "send",
    }
    calls = [
        ast.unparse(node.func).lower()
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr.lower() in http_methods
    ]
    assert calls == ["self._client.get"]


def test_client_does_not_issue_post_or_put_requests() -> None:
    tree = _client_tree()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute):
            assert node.func.attr.lower() not in {"post", "put"}
            assert node.func.attr.lower() != "request", (
                "use the single GET method rather than a generic request method"
            )
        if isinstance(node.func, ast.Name):
            assert node.func.id.lower() not in {"post", "put", "request"}


def test_no_verify_false_kwarg_in_client_source() -> None:
    tree = _client_tree()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    raise AssertionError("client must never pass verify=False")


def test_no_signing_or_broadcast_imports_in_client_source() -> None:
    tree = _client_tree()
    banned_parts = {
        "sign", "signer", "signing", "broadcast", "broadcaster", "sendrawtransaction",
    }
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""] + [alias.name for alias in node.names]
        for name in names:
            parts = set(name.lower().replace(".", "_").split("_"))
            assert not parts.intersection(banned_parts), (
                f"client must not import signing/broadcast symbol {name!r}"
            )


def test_default_allowlist_is_mempool_space() -> None:
    assert DEFAULT_ALLOWLIST == ("https://mempool.space",)
