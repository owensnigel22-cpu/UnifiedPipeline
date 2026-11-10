"""Tests for exact Bitcoin Core descriptor UTXO scanning."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from keylab.wallet.utxo import UTXOScanError, btc_to_sats, scan_utxos

_TIP = "11" * 32
_TXID = "22" * 32
_GENERATOR_PUBKEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
_GENERATOR_PKH = "751e76e8199196d454941c45d1b3a323f1433bd6"


class _FakeScanner:
    def __init__(self, scan_result: dict[str, Any], *, after_tip: str = _TIP) -> None:
        self.scan_result = scan_result
        self.tips = [_TIP, after_tip]
        self.scan_objects: list[list[str | dict[str, Any]]] = []

    def getblockchaininfo(self) -> dict[str, Any]:
        return {"chain": "regtest", "blocks": 100, "bestblockhash": self.tips.pop(0)}

    def scantxoutset(self, scan_objects: list[str | dict[str, Any]]) -> dict[str, Any]:
        self.scan_objects.append(scan_objects)
        return self.scan_result


def _result(*, descriptor: str = f"wpkh({_GENERATOR_PUBKEY})") -> dict[str, Any]:
    return {
        "success": True,
        "bestblock": _TIP,
        "height": 100,
        "txouts": 12,
        "unspents": [
            {
                "txid": _TXID,
                "vout": 3,
                "scriptPubKey": "0014" + _GENERATOR_PKH,
                "desc": descriptor,
                "amount": Decimal("0.00001234"),
                "height": 80,
            }
        ],
    }


@pytest.mark.parametrize(
    ("amount", "expected"),
    [
        (Decimal("0.00000001"), 1),
        ("0.12345678", 12_345_678),
        (2, 200_000_000),
    ],
)
def test_btc_to_sats_preserves_exact_decimal_values(amount: Decimal | str | int, expected: int) -> None:
    assert btc_to_sats(amount) == expected


@pytest.mark.parametrize("amount", [Decimal("0.000000001"), Decimal("-0.1"), Decimal("NaN"), 21000001])
def test_btc_to_sats_rejects_fractional_negative_nonfinite_and_excess_values(amount: Any) -> None:
    with pytest.raises(ValueError):
        btc_to_sats(amount)


def test_btc_to_sats_rejects_float_inputs() -> None:
    with pytest.raises(TypeError, match="floats"):
        btc_to_sats(0.1)  # type: ignore[arg-type]


def test_scan_utxos_returns_confirmed_outpoints_and_checks_chain_tip() -> None:
    node = _FakeScanner(_result())

    descriptor = f"wpkh({_GENERATOR_PUBKEY})"
    scan = scan_utxos(node, descriptor, range_end=5)

    assert scan.bestblock == _TIP
    assert scan.height == 100
    assert scan.scanned_txouts == 12
    assert scan.utxos[0].outpoint == (_TXID, 3)
    assert scan.utxos[0].value_sats == 1_234
    assert scan.utxos[0].input_vbytes == 68
    assert node.scan_objects == [[{"desc": descriptor, "range": [0, 5]}]]


def test_scan_utxos_supports_nested_witness_and_rejects_unsupported_scripts() -> None:
    import hashlib

    redeem = b"\x00\x14" + bytes.fromhex(_GENERATOR_PKH)
    script = b"\xa9\x14" + hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).digest() + b"\x87"
    descriptor = f"sh(wpkh({_GENERATOR_PUBKEY}))"
    result = _result(descriptor=descriptor)
    result["unspents"][0]["scriptPubKey"] = script.hex()
    node = _FakeScanner(result)
    scan = scan_utxos(node, descriptor)
    assert scan.utxos[0].input_vbytes == 91
    assert scan.utxos[0].redeem_script == redeem

    unsupported_descriptor = "pkh(" + "11" * 33 + ")"
    with pytest.raises(UTXOScanError, match="only P2WPKH"):
        scan_utxos(_FakeScanner(_result(descriptor=unsupported_descriptor)), unsupported_descriptor)


def test_scan_utxos_rejects_private_descriptors_and_stale_or_incomplete_scans() -> None:
    node = _FakeScanner(_result())
    with pytest.raises(ValueError, match="private extended keys"):
        scan_utxos(node, "wpkh(xprv-private-material)")
    assert node.scan_objects == []

    with pytest.raises(UTXOScanError, match="tip changed"):
        scan_utxos(_FakeScanner(_result(), after_tip="44" * 32), f"wpkh({_GENERATOR_PUBKEY})")
    with pytest.raises(UTXOScanError, match="did not complete"):
        scan_utxos(_FakeScanner({"success": False}), f"wpkh({_GENERATOR_PUBKEY})")
