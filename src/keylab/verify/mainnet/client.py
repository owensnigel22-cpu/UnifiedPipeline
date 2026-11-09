"""Read-only HTTPS client for public block explorers (mempool.space by default).

Role: fetch **public** chain artifacts (transactions, block headers, merkle
proofs, UTXO records) over TLS as **data only**. Every cryptographic judgement is
made locally by the caller; this client never decides validity.

Hard read-only boundary (checked structurally, see tests/test_verify_client.py
AST test): the only HTTP verb is GET (one private ``_get``); there is **no**
POST/PUT/PATCH/DELETE, no broadcast, no signing, no private-key handling, and no
way to disable TLS certificate verification. TLS 1.2+ is enforced and a
non-``https://`` URL raises before any socket opens. See SECURITY.md.
"""

from __future__ import annotations

import ssl
from typing import Self
from urllib.parse import urlsplit

import httpx

__all__ = ["DEFAULT_ALLOWLIST", "ReadOnlyExplorerClient"]

DEFAULT_ALLOWLIST: tuple[str, ...] = ("https://mempool.space",)


def _tls_context() -> ssl.SSLContext:
    """A TLS 1.2+ context with certificate validation on; no insecure overrides."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _normalise_base(base: str) -> str:
    origin = _https_origin(base)
    parsed = urlsplit(base)
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("explorer base URL must not include a path, query, or fragment")
    return origin


def _https_origin(url: str) -> str:
    if not isinstance(url, str):
        raise TypeError("explorer URL must be a string")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid explorer URL: {url!r}") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ValueError(f"explorer URL must use https:// and include a host: {url!r}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credentials are not permitted in explorer URLs")
    if port is not None and port < 1:
        raise ValueError("explorer URL port must be positive")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" + (f":{port}" if port not in (None, 443) else "")


class ReadOnlyExplorerClient:
    """GET-only, TLS-1.2+, allow-listed client. Fetches bytes; verifies nothing."""

    def __init__(
        self,
        allowlist: tuple[str, ...] = DEFAULT_ALLOWLIST,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 15.0,
    ) -> None:
        self._allowlist = tuple(_normalise_base(base) for base in allowlist)
        if not self._allowlist:
            raise ValueError("allowlist must contain at least one https:// base URL")
        self._client = httpx.Client(
            verify=_tls_context(), timeout=timeout, transport=transport,
            headers={"User-Agent": "keylab-verify/readonly"}, follow_redirects=False,
        )

    @property
    def allowlist(self) -> tuple[str, ...]:
        return self._allowlist

    def _check_url(self, url: str) -> None:
        origin = _https_origin(url)
        if origin not in self._allowlist:
            raise ValueError(f"host {origin!r} is not on the allow-list {self._allowlist}")

    def _get(self, path: str, *, base: str | None = None) -> httpx.Response:
        """The single network egress: an HTTPS GET to an allow-listed host."""
        target = _normalise_base(base) if base is not None else self._allowlist[0]
        url = target + path
        self._check_url(url)
        response = self._client.get(url)
        response.raise_for_status()
        return response

    # --- public read-only fetchers -------------------------------------------------------------

    def get_transaction(self, txid: str, *, base: str | None = None) -> dict:
        """Fetch a transaction as JSON (``GET /api/tx/<txid>``)."""
        return self._get(f"/api/tx/{_hex(txid, 32)}", base=base).json()

    def get_transaction_hex(self, txid: str, *, base: str | None = None) -> bytes:
        """Fetch the raw transaction bytes (``GET /api/tx/<txid>/hex``)."""
        return bytes.fromhex(self._get(f"/api/tx/{_hex(txid, 32)}/hex", base=base).text.strip())

    def get_block_hash_at_height(self, height: int, *, base: str | None = None) -> str:
        """Fetch the block hash at a height (``GET /api/block-height/<n>``)."""
        if type(height) is not int or height < 0:
            raise ValueError("height must be a non-negative int")
        return self._get(f"/api/block-height/{height}", base=base).text.strip()

    def get_block_header(self, block_hash: str, *, base: str | None = None) -> bytes:
        """Fetch the 80-byte block header (``GET /api/block/<hash>/header``)."""
        return bytes.fromhex(self._get(f"/api/block/{_hex(block_hash, 32)}/header", base=base).text.strip())

    def get_merkle_proof(self, txid: str, *, base: str | None = None) -> dict:
        """Fetch a tx's merkle inclusion proof (``GET /api/tx/<txid>/merkle-proof``)."""
        return self._get(f"/api/tx/{_hex(txid, 32)}/merkle-proof", base=base).json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _hex(value: str, nbytes: int) -> str:
    """Validate a lowercase hex id of exactly ``nbytes`` bytes (defends path building)."""
    if not isinstance(value, str) or len(value) != nbytes * 2:
        raise ValueError(f"expected a {nbytes}-byte hex string, got {value!r}")
    int(value, 16)  # raises ValueError on non-hex
    return value.lower()
