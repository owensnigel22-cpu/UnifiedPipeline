"""Broadcast a pre-signed Bitcoin transaction via public HTTP explorer APIs.

These broadcasters take an **already-signed** raw transaction hex and push it to
the network over TLS; they handle **no private keys** and perform no signing. TLS
1.2+ with certificate validation is enforced and there is no insecure override.

Signing a mainnet transaction remains governed by the wallet's signing path (use
the audited coincurve/libsecp256k1 backend for real funds); the pure-Python ECC
is non-constant-time and unsuitable for secret keys. See SECURITY.md.
"""

from __future__ import annotations

import ssl
from typing import ClassVar, Protocol, Self
from urllib.parse import urlparse

import httpx

from keylab.verify.node import Network

__all__ = [
    "BlockCypherBroadcaster",
    "BroadcastError",
    "Broadcaster",
    "MempoolSpaceBroadcaster",
]


class BroadcastError(RuntimeError):
    """A broadcast was rejected by the explorer (``already_known`` if the tx was already seen)."""

    def __init__(self, message: str, *, status: int | None = None, already_known: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.already_known = already_known


class Broadcaster(Protocol):
    """Anything that pushes a signed raw transaction and returns its txid."""

    def broadcast(self, raw_tx_hex: str) -> str: ...


def _tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _require_https(base: str) -> str:
    if not isinstance(base, str) or not base.startswith("https://"):
        raise ValueError(f"broadcaster base URL must be https://, got {base!r}")
    if not urlparse(base).netloc:
        raise ValueError(f"broadcaster base URL has no host: {base!r}")
    return base.rstrip("/")


def _validate_tx_hex(raw_tx_hex: str) -> str:
    if not isinstance(raw_tx_hex, str) or not raw_tx_hex:
        raise ValueError("raw_tx_hex must be a non-empty hex string")
    if len(raw_tx_hex) % 2 or len(raw_tx_hex) < 20:
        raise ValueError("raw_tx_hex is not a plausible transaction hex")
    int(raw_tx_hex, 16)  # raises on non-hex
    return raw_tx_hex.lower()


def _is_already_known(reason: str) -> bool:
    low = reason.lower()
    return any(token in low for token in ("already in", "already known", "txn-already", "duplicate"))


class MempoolSpaceBroadcaster:
    """Push a signed tx via ``POST {base}/api/tx`` (mempool.space)."""

    _BASES: ClassVar[dict[Network, str]] = {
        Network.MAINNET: "https://mempool.space",
        Network.TESTNET: "https://mempool.space/testnet",
    }

    def __init__(
        self, network: Network = Network.MAINNET, *, base: str | None = None,
        transport: httpx.BaseTransport | None = None, timeout: float = 20.0,
    ) -> None:
        if base is None:
            if network not in self._BASES:
                raise ValueError(f"mempool.space has no public endpoint for {network}")
            base = self._BASES[network]
        self._base = _require_https(base)
        self._client = httpx.Client(
            verify=_tls_context(), timeout=timeout, transport=transport,
            headers={"User-Agent": "keylab-wallet/broadcast"}, follow_redirects=False,
        )

    def broadcast(self, raw_tx_hex: str) -> str:
        tx_hex = _validate_tx_hex(raw_tx_hex)
        response = self._client.post(f"{self._base}/api/tx", content=tx_hex)
        if response.status_code >= 400:
            reason = response.text.strip() or f"HTTP {response.status_code}"
            raise BroadcastError(
                f"mempool.space rejected the transaction: {reason}",
                status=response.status_code, already_known=_is_already_known(reason),
            )
        return response.text.strip()  # the accepted txid

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class BlockCypherBroadcaster:
    """Push a signed tx via ``POST {base}/v1/btc/<chain>/txs/push`` (BlockCypher)."""

    _CHAINS: ClassVar[dict[Network, str]] = {Network.MAINNET: "main", Network.TESTNET: "test3"}

    def __init__(
        self, network: Network = Network.MAINNET, *, base: str = "https://api.blockcypher.com",
        token: str | None = None, transport: httpx.BaseTransport | None = None, timeout: float = 20.0,
    ) -> None:
        if network not in self._CHAINS:
            raise ValueError(f"BlockCypher has no public endpoint for {network}")
        self._path = f"/v1/btc/{self._CHAINS[network]}/txs/push"
        self._base = _require_https(base)
        self._params = {"token": token} if token else {}
        self._client = httpx.Client(
            verify=_tls_context(), timeout=timeout, transport=transport,
            headers={"User-Agent": "keylab-wallet/broadcast"}, follow_redirects=False,
        )

    def broadcast(self, raw_tx_hex: str) -> str:
        tx_hex = _validate_tx_hex(raw_tx_hex)
        response = self._client.post(f"{self._base}{self._path}", json={"tx": tx_hex}, params=self._params)
        if response.status_code >= 400:
            reason = (response.text or "").strip() or f"HTTP {response.status_code}"
            raise BroadcastError(
                f"BlockCypher rejected the transaction: {reason}",
                status=response.status_code, already_known=_is_already_known(reason),
            )
        payload = response.json()
        txid = payload.get("tx", {}).get("hash")
        if not isinstance(txid, str):
            raise BroadcastError("BlockCypher response did not contain a transaction hash", status=response.status_code)
        return txid

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
