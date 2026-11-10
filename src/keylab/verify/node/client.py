"""Small, pooled HTTP JSON-RPC client for Bitcoin Core.

This client intentionally does not retry mutating calls. In particular, a
timeout from ``sendrawtransaction`` leaves acceptance ambiguous and must not
trigger an automatic second submission.
"""

from __future__ import annotations

import ipaddress
import json
import re
import threading
import warnings
from collections.abc import Sequence
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self
from urllib.parse import urlsplit

from keylab.verify.node.models import Network

if TYPE_CHECKING:
    import httpx


class BitcoinRPCError(RuntimeError):
    """An HTTP, protocol, or Bitcoin Core JSON-RPC failure."""

    def __init__(self, method: str, message: str, *, code: int | None = None) -> None:
        super().__init__(f"Bitcoin Core RPC {method!r} failed: {message}")
        self.method = method
        self.code = code


class BitcoinRPCClient:
    """Call Bitcoin Core JSON-RPC over a pooled HTTP connection.

    ``cookie_file`` is preferred for a local node. Alternatively, pass both
    ``rpc_user`` and ``rpc_password``. Credentials are read/applied at request
    time and never placed in the URL or emitted in errors.

    A warning is emitted for a non-loopback HTTP endpoint because Basic
    authentication does not encrypt the credentials or RPC payload. Remote
    endpoints should use HTTPS or a separately secured tunnel.
    """

    _READ_METHODS = frozenset(
        {"getblockchaininfo", "gettxout", "getrawtransaction", "testmempoolaccept", "scantxoutset"}
    )

    def __init__(
        self,
        url: str = "http://127.0.0.1:18443/",
        *,
        cookie_file: str | Path | None = None,
        rpc_user: str | None = None,
        rpc_password: str | None = None,
        timeout: float = 15.0,
        max_connections: int = 4,
        transport: Any = None,
    ) -> None:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("RPC URL must be an http(s) URL with a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("RPC credentials must not be embedded in the URL")
        if parsed.query or parsed.fragment:
            raise ValueError("RPC URL must not contain a query string or fragment")
        if not urlsplit(url).path:
            url = url.rstrip("/") + "/"
        if (rpc_user is None) != (rpc_password is None):
            raise ValueError("rpc_user and rpc_password must be supplied together")
        if cookie_file is not None and rpc_user is not None:
            raise ValueError("choose cookie_file or Basic authentication, not both")
        if type(timeout) not in {int, float} or timeout <= 0:
            raise ValueError("timeout must be a positive number")
        if type(max_connections) is not int or max_connections < 1:
            raise ValueError("max_connections must be a positive integer")

        hostname = parsed.hostname.lower().rstrip(".")
        try:
            loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            loopback = hostname == "localhost"
        if parsed.scheme != "https" and not loopback:
            warnings.warn(
                "Bitcoin Core RPC over HTTP to a non-loopback host is unencrypted; "
                "use HTTPS or a separately secured tunnel",
                RuntimeWarning,
                stacklevel=2,
            )

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - exercised without the optional test env
            raise RuntimeError("BitcoinRPCClient requires the project httpx dependency") from exc

        self._url = url
        self._cookie_file = Path(cookie_file) if cookie_file is not None else None
        self._rpc_user = rpc_user
        self._rpc_password = rpc_password
        self._timeout = float(timeout)
        self._httpx: Any = httpx
        self._client: httpx.Client = httpx.Client(
            timeout=httpx.Timeout(self._timeout),
            limits=httpx.Limits(
                max_connections=max_connections,
                max_keepalive_connections=max_connections,
            ),
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )
        self._request_lock = threading.Lock()
        self._request_id = 0

    def _next_id(self) -> int:
        with self._request_lock:
            self._request_id += 1
            return self._request_id

    def _auth(self) -> Any:
        if self._cookie_file is not None:
            try:
                cookie = self._cookie_file.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise BitcoinRPCError("authentication", "could not read RPC cookie") from exc
            username, separator, password = cookie.partition(":")
            if not separator or not username or not password:
                raise BitcoinRPCError("authentication", "RPC cookie has invalid format")
            return (username, password)
        if self._rpc_user is not None and self._rpc_password is not None:
            return (self._rpc_user, self._rpc_password)
        return None

    def call(self, method: str, params: Sequence[Any] = ()) -> Any:
        """Call an allow-listed read/preflight method; sends require the guard below."""
        if method not in self._READ_METHODS:
            raise RuntimeError("RPC method is not exposed; use the guarded broadcast API for sends")
        return self._call_rpc(method, params)

    def _call_rpc(self, method: str, params: Sequence[Any]) -> Any:
        """Make one validated JSON-RPC 1.0 call for an allow-listed internal use."""
        if not isinstance(method, str) or re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", method) is None:
            raise ValueError("RPC method must be an alphanumeric method name")
        if isinstance(params, (str, bytes, bytearray)):
            raise TypeError("RPC params must be a sequence of values")
        request_id = self._next_id()
        payload = {
            "jsonrpc": "1.0",
            "id": request_id,
            "method": method,
            "params": list(params),
        }
        try:
            response = self._client.post(
                self._url,
                content=json.dumps(payload, separators=(",", ":")),
                headers={"Content-Type": "application/json"},
                auth=self._auth(),
                timeout=self._timeout,
            )
        except Exception as exc:
            # Do not propagate request exception strings: some transports echo
            # request URLs or headers that could contain sensitive details.
            if isinstance(exc, self._httpx.HTTPError):
                raise BitcoinRPCError(method, "HTTP transport failed") from exc
            raise

        try:
            # Decimal parsing preserves Bitcoin Core's BTC-denominated amount
            # fields without a binary float round trip.
            body = json.loads(response.text, parse_float=Decimal)
        except (ValueError, json.JSONDecodeError) as exc:
            raise BitcoinRPCError(method, "node returned invalid JSON") from exc
        if not isinstance(body, dict):
            raise BitcoinRPCError(method, "node returned a non-object JSON response")
        if body.get("id") != request_id:
            raise BitcoinRPCError(method, "node returned a mismatched request id")
        error = body.get("error")
        if error is not None:
            if isinstance(error, dict):
                message = error.get("message")
                code = error.get("code")
                safe_message = message if isinstance(message, str) else "RPC error"
                safe_code = code if type(code) is int else None
                raise BitcoinRPCError(method, safe_message, code=safe_code)
            raise BitcoinRPCError(method, "node returned an invalid RPC error")
        if response.is_error:
            raise BitcoinRPCError(method, f"HTTP status {response.status_code}")
        if "result" not in body:
            raise BitcoinRPCError(method, "node response has no result")
        return body["result"]

    def getblockchaininfo(self) -> dict[str, Any]:
        """Return validated chain identity and synchronization metadata."""
        result = self.call("getblockchaininfo")
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("chain"), str)
            or type(result.get("blocks")) is not int
        ):
            raise BitcoinRPCError("getblockchaininfo", "node returned malformed chain information")
        return result

    def gettxout(
        self,
        txid: str,
        vout: int,
        *,
        include_mempool: bool = True,
    ) -> dict[str, Any] | None:
        """Return one unspent output, or ``None`` if it is spent/unavailable."""
        self._validate_txid(txid)
        if type(vout) is not int or vout < 0:
            raise ValueError("vout must be a non-negative integer")
        if type(include_mempool) is not bool:
            raise TypeError("include_mempool must be bool")
        result = self.call("gettxout", (txid.lower(), vout, include_mempool))
        if result is not None and not isinstance(result, dict):
            raise BitcoinRPCError("gettxout", "node returned malformed output information")
        return result

    def getrawtransaction(
        self,
        txid: str,
        *,
        verbose: bool = False,
        blockhash: str | None = None,
    ) -> str | dict[str, Any]:
        """Fetch a raw transaction by txid (requiring txindex or blockhash as applicable)."""
        self._validate_txid(txid)
        if type(verbose) is not bool:
            raise TypeError("verbose must be bool")
        if blockhash is not None:
            self._validate_txid(blockhash, field="blockhash")
        params: tuple[Any, ...] = (txid.lower(), verbose)
        if blockhash is not None:
            params += (blockhash.lower(),)
        result = self.call("getrawtransaction", params)
        if verbose and not isinstance(result, dict):
            raise BitcoinRPCError("getrawtransaction", "node returned malformed transaction metadata")
        if not verbose and not isinstance(result, str):
            raise BitcoinRPCError("getrawtransaction", "node returned non-hex transaction data")
        return result

    def testmempoolaccept(self, transactions: Sequence[str]) -> list[dict[str, Any]]:
        """Ask the node to check transactions without submitting them to its mempool."""
        txs = tuple(transactions)
        if not txs:
            raise ValueError("transactions must not be empty")
        for raw_tx in txs:
            if not isinstance(raw_tx, str) or not raw_tx or len(raw_tx) % 2:
                raise ValueError("each transaction must be non-empty even-length hex")
            try:
                bytes.fromhex(raw_tx)
            except ValueError as exc:
                raise ValueError("each transaction must be hexadecimal") from exc
        result = self.call("testmempoolaccept", (list(txs),))
        if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
            raise BitcoinRPCError("testmempoolaccept", "node returned malformed acceptance results")
        return result

    def scantxoutset(self, scan_objects: Sequence[str | dict[str, Any]]) -> dict[str, Any]:
        """Scan the current UTXO set for descriptors using Bitcoin Core RPC."""
        objects = tuple(scan_objects)
        if not objects:
            raise ValueError("scan_objects must not be empty")
        for scan_object in objects:
            descriptor = scan_object if isinstance(scan_object, str) else scan_object.get("desc")
            if not isinstance(descriptor, str) or not descriptor.strip():
                raise ValueError("each scan object must contain a non-empty descriptor")
        result = self.call("scantxoutset", ("start", list(objects)))
        if not isinstance(result, dict) or type(result.get("success")) is not bool:
            raise BitcoinRPCError("scantxoutset", "node returned malformed scan results")
        if result["success"] and not isinstance(result.get("unspents"), list):
            raise BitcoinRPCError("scantxoutset", "node returned malformed unspent results")
        return result

    def sendrawtransaction(
        self,
        raw_tx: str,
        *,
        network: Network,
        confirm_test_network: bool,
    ) -> str:
        """Submit once only after explicit confirmation and a matching test chain.

        Mainnet rejection is unconditional. ``call('sendrawtransaction', ...)``
        is blocked, so this guarded method is the only exposed raw-transaction
        submission path in the client.
        """
        if network is Network.MAINNET:
            raise RuntimeError("mainnet broadcasting is disabled in M12")
        if not isinstance(network, Network):
            raise TypeError("network must be a Network value")
        if type(confirm_test_network) is not bool or not confirm_test_network:
            raise RuntimeError("explicit test-network confirmation is required to broadcast")
        if not isinstance(raw_tx, str) or not raw_tx or len(raw_tx) % 2:
            raise ValueError("transaction must be non-empty even-length hex")
        try:
            bytes.fromhex(raw_tx)
        except ValueError as exc:
            raise ValueError("transaction must be hexadecimal") from exc
        chain_info = self.getblockchaininfo()
        if chain_info["chain"] != network.rpc_chain:
            raise RuntimeError(
                f"configured network {network.value!r} does not match node chain {chain_info['chain']!r}"
            )
        result = self._call_rpc("sendrawtransaction", (raw_tx,))
        if not isinstance(result, str) or re.fullmatch(r"[0-9a-fA-F]{64}", result) is None:
            raise BitcoinRPCError("sendrawtransaction", "node returned an invalid transaction id")
        return result.lower()

    @staticmethod
    def _validate_txid(value: str, *, field: str = "txid") -> None:
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
            raise ValueError(f"{field} must be 64 hexadecimal characters")

    def close(self) -> None:
        """Close the pooled HTTP client."""
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
