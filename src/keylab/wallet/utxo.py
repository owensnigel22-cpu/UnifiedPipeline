"""Descriptor-based confirmed-UTXO discovery through Bitcoin Core."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Protocol

_SATOSHIS_PER_BTC = 100_000_000
_MAX_MONEY_SATS = 21_000_000 * _SATOSHIS_PER_BTC
_TXID_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
_PRIVATE_EXTENDED_KEY_MARKER_RE = re.compile(r"(?:xprv|tprv|yprv|zprv|uprv|vprv)", re.IGNORECASE)
_BASE58_TOKEN_RE = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{51,52}(?![1-9A-HJ-NP-Za-km-z])")


class NodeScanner(Protocol):
    def getblockchaininfo(self) -> dict[str, Any]: ...

    def scantxoutset(self, scan_objects: list[str | dict[str, Any]]) -> dict[str, Any]: ...


class UTXOScanError(RuntimeError):
    """Raised for incomplete, stale, malformed, or unsupported UTXO scans."""


@dataclass(frozen=True)
class UTXO:
    """A confirmed unspent output matching one public output descriptor."""

    txid: str
    vout: int
    value_sats: int
    script_pubkey: bytes
    descriptor: str
    height: int
    input_vbytes: int

    @property
    def outpoint(self) -> tuple[str, int]:
        return self.txid, self.vout


@dataclass(frozen=True)
class UTXOScan:
    """UTXO results tied to the exact best block reported by the node scan."""

    bestblock: str
    height: int
    scanned_txouts: int
    utxos: tuple[UTXO, ...]


def btc_to_sats(amount: Decimal | int | str) -> int:
    """Convert an exact BTC amount to satoshis, rejecting fractional sats."""
    if isinstance(amount, (bool, float)):
        raise TypeError("BTC amount must be Decimal, int, or decimal string; floats are not accepted")
    try:
        exact_amount = amount if isinstance(amount, Decimal) else Decimal(amount)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("BTC amount is not a valid decimal") from exc
    if not exact_amount.is_finite() or exact_amount < 0:
        raise ValueError("BTC amount must be finite and non-negative")
    satoshis = exact_amount * _SATOSHIS_PER_BTC
    if satoshis != satoshis.to_integral_value():
        raise ValueError("BTC amount contains a fraction of a satoshi")
    result = int(satoshis)
    if result > _MAX_MONEY_SATS:
        raise ValueError("BTC amount exceeds the maximum money supply")
    return result


def _descriptor_input_vbytes(descriptor: str) -> int:
    normalized = descriptor.strip().lower()
    if normalized.startswith("sh(wpkh("):
        return 91
    if normalized.startswith("wpkh("):
        return 68
    raise UTXOScanError(
        "only P2WPKH and P2SH-P2WPKH descriptors are supported by the current PSBT signer"
    )


def _reject_private_descriptor(descriptor: str) -> None:
    if _PRIVATE_EXTENDED_KEY_MARKER_RE.search(descriptor):
        raise ValueError("private extended keys must never be sent to the node")
    from keylab.encoding.wif import decode as decode_wif

    for match in _BASE58_TOKEN_RE.finditer(descriptor):
        try:
            decode_wif(match.group(0))
        except ValueError:
            continue
        raise ValueError("private WIF material must never be sent to the node")


def _parse_unspent(raw: Mapping[str, Any]) -> UTXO:
    txid = raw.get("txid")
    vout = raw.get("vout")
    descriptor = raw.get("desc")
    script_hex = raw.get("scriptPubKey")
    height = raw.get("height")
    if not isinstance(txid, str) or _TXID_RE.fullmatch(txid) is None:
        raise UTXOScanError("node returned an invalid UTXO txid")
    if type(vout) is not int or vout < 0:
        raise UTXOScanError("node returned an invalid UTXO output index")
    if not isinstance(descriptor, str) or not descriptor.strip():
        raise UTXOScanError("node returned a UTXO without a descriptor")
    if not isinstance(script_hex, str):
        raise UTXOScanError("node returned a UTXO without a scriptPubKey")
    try:
        script_pubkey = bytes.fromhex(script_hex)
    except ValueError as exc:
        raise UTXOScanError("node returned a malformed scriptPubKey") from exc
    if not script_pubkey:
        raise UTXOScanError("node returned an empty scriptPubKey")
    if type(height) is not int or height < 0:
        raise UTXOScanError("node returned an invalid UTXO height")
    amount = raw.get("amount")
    if isinstance(amount, bool) or not isinstance(amount, (Decimal, int, str)):
        raise UTXOScanError("node returned a UTXO amount with an unsupported numeric type")
    try:
        value_sats = btc_to_sats(amount)
        input_vbytes = _descriptor_input_vbytes(descriptor)
    except (TypeError, ValueError, UTXOScanError) as exc:
        raise UTXOScanError(f"node returned an invalid or unsupported UTXO: {exc}") from exc
    return UTXO(
        txid=txid.lower(),
        vout=vout,
        value_sats=value_sats,
        script_pubkey=script_pubkey,
        descriptor=descriptor,
        height=height,
        input_vbytes=input_vbytes,
    )


def scan_utxos(
    client: NodeScanner,
    descriptor: str,
    *,
    range_end: int | None = None,
    max_unspents: int = 100_000,
) -> UTXOScan:
    """Scan Core's current chain UTXO set for one public descriptor.

    ``scantxoutset`` is not a historical address index and does not return
    mempool-created outputs. The scan is rejected if the chain tip changed
    between the surrounding node queries. Unconfirmed inputs are unsupported.
    """
    if not isinstance(descriptor, str) or not descriptor.strip():
        raise ValueError("descriptor must be a non-empty string")
    _reject_private_descriptor(descriptor)
    _descriptor_input_vbytes(descriptor)
    if range_end is not None and (type(range_end) is not int or range_end < 0):
        raise ValueError("range_end must be a non-negative integer")
    if type(max_unspents) is not int or max_unspents < 1:
        raise ValueError("max_unspents must be a positive integer")

    before = client.getblockchaininfo()
    before_tip = before.get("bestblockhash")
    if not isinstance(before_tip, str) or _TXID_RE.fullmatch(before_tip) is None:
        raise UTXOScanError("node did not report a valid chain tip before scanning")
    scan_object: str | dict[str, Any]
    if range_end is None:
        scan_object = descriptor
    else:
        scan_object = {"desc": descriptor, "range": [0, range_end]}
    response = client.scantxoutset([scan_object])
    if response.get("success") is not True:
        raise UTXOScanError("node UTXO scan did not complete")
    bestblock = response.get("bestblock")
    height = response.get("height")
    txouts = response.get("txouts")
    raw_unspents = response.get("unspents")
    if not isinstance(bestblock, str) or _TXID_RE.fullmatch(bestblock) is None:
        raise UTXOScanError("node returned an invalid scan tip")
    if type(height) is not int or height < 0 or type(txouts) is not int or txouts < 0:
        raise UTXOScanError("node returned invalid scan counts")
    if not isinstance(raw_unspents, list):
        raise UTXOScanError("node returned malformed UTXO results")
    if len(raw_unspents) > max_unspents:
        raise UTXOScanError("UTXO scan exceeded max_unspents")
    after = client.getblockchaininfo()
    after_tip = after.get("bestblockhash")
    if before_tip.lower() != bestblock.lower() or bestblock.lower() != str(after_tip).lower():
        raise UTXOScanError("chain tip changed during UTXO scan; run the scan again")

    utxos = tuple(_parse_unspent(item) if isinstance(item, Mapping) else _invalid_unspent() for item in raw_unspents)
    if len({utxo.outpoint for utxo in utxos}) != len(utxos):
        raise UTXOScanError("node returned duplicate UTXOs")
    return UTXOScan(bestblock.lower(), height, txouts, utxos)


def _invalid_unspent() -> UTXO:
    raise UTXOScanError("node returned a malformed UTXO record")


__all__ = ["UTXO", "UTXOScan", "UTXOScanError", "btc_to_sats", "scan_utxos"]
