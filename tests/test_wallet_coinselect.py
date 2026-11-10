"""Tests for bounded Branch-and-Bound selection and Core dust thresholds."""

from __future__ import annotations

import pytest

from keylab.wallet.coinselect import CoinSelectionError, dust_threshold, select_coins_bnb
from keylab.wallet.utxo import UTXO

_P2WPKH = b"\x00\x14" + b"\x11" * 20
_P2SH = b"\xa9\x14" + b"\x22" * 20 + b"\x87"
_P2PKH = b"\x76\xa9\x14" + b"\x33" * 20 + b"\x88\xac"


def _utxo(index: int, amount: int) -> UTXO:
    return UTXO(
        txid=f"{index:02x}" * 32,
        vout=index,
        value_sats=amount,
        script_pubkey=_P2WPKH,
        descriptor="wpkh(test-public-key)",
        height=1,
        input_vbytes=68,
    )


def test_dust_threshold_matches_bitcoin_core_default_for_common_outputs() -> None:
    assert dust_threshold(_P2PKH) == 546
    assert dust_threshold(_P2WPKH) == 294
    assert dust_threshold(_P2SH) == 540
    assert dust_threshold(b"\x6a\x01\x01") == 0
    assert dust_threshold(_P2WPKH, dust_relay_fee_sat_kvb=6_000) == 588


def test_bnb_selection_estimates_fees_and_returns_economic_change() -> None:
    result = select_coins_bnb(
        [_utxo(1, 10_000)],
        9_000,
        fee_rate_sat_vb="2",
        destination_script_pubkey=_P2WPKH,
        change_script_pubkey=_P2WPKH,
        max_fee_sats=1_000,
    )
    assert result.total_input_sats == 10_000
    assert result.estimated_vbytes == 141
    assert result.fee_sats == 282
    assert result.change_sats == 718
    assert result.search_complete


def test_bnb_omits_dust_change_and_adds_remainder_to_fee() -> None:
    result = select_coins_bnb(
        [_utxo(1, 9_500)],
        9_000,
        fee_rate_sat_vb=2,
        destination_script_pubkey=_P2WPKH,
        change_script_pubkey=_P2WPKH,
        max_fee_sats=1_000,
    )
    assert result.change_sats == 0
    assert result.fee_sats == 500
    assert result.waste_sats == 280


def test_bnb_prefers_lower_waste_combination_and_reports_budget_completion() -> None:
    result = select_coins_bnb(
        [_utxo(1, 6_000), _utxo(2, 5_000), _utxo(3, 9_500)],
        9_000,
        fee_rate_sat_vb=2,
        destination_script_pubkey=_P2WPKH,
        change_script_pubkey=_P2WPKH,
        max_fee_sats=1_000,
        max_nodes=100,
    )
    assert len(result.utxos) == 2
    assert result.total_input_sats == 11_000
    assert result.waste_sats == 198
    assert result.search_complete

    bounded = select_coins_bnb(
        [_utxo(1, 10_000), _utxo(2, 5_000)],
        9_000,
        fee_rate_sat_vb=2,
        destination_script_pubkey=_P2WPKH,
        change_script_pubkey=_P2WPKH,
        max_fee_sats=1_000,
        max_nodes=2,
    )
    assert bounded.nodes_visited == 2
    assert not bounded.search_complete


def test_bnb_rejects_unsafe_limits_or_insufficient_funds() -> None:
    with pytest.raises(CoinSelectionError, match="cannot cover"):
        select_coins_bnb(
            [_utxo(1, 100)],
            9_000,
            fee_rate_sat_vb=2,
            destination_script_pubkey=_P2WPKH,
            change_script_pubkey=_P2WPKH,
            max_fee_sats=1_000,
        )
    with pytest.raises(ValueError, match="positive integer"):
        select_coins_bnb(
            [_utxo(1, 10_000)],
            9_000,
            fee_rate_sat_vb=2,
            destination_script_pubkey=_P2WPKH,
            change_script_pubkey=_P2WPKH,
            max_fee_sats=1_000,
            max_nodes=0,
        )
    with pytest.raises(ValueError, match="change script"):
        select_coins_bnb(
            [_utxo(1, 10_000)],
            9_000,
            fee_rate_sat_vb=2,
            destination_script_pubkey=_P2WPKH,
            change_script_pubkey=_P2PKH,
            max_fee_sats=1_000,
        )
