"""Bounded Branch-and-Bound UTXO selection with Bitcoin Core dust policy."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal, InvalidOperation

from keylab.wallet.utxo import UTXO

_DEFAULT_DUST_RELAY_FEE_SAT_KVB = 3_000
_MIN_WITNESS_INPUT_VBYTES = 68
_P2SH_P2WPKH_INPUT_VBYTES = 91
_TX_OVERHEAD_VBYTES = 11


class CoinSelectionError(ValueError):
    """No safe coin selection could be produced under the supplied bounds."""


@dataclass(frozen=True)
class CoinSelection:
    """Selected inputs and exact fee/change accounting for one spend."""

    utxos: tuple[UTXO, ...]
    total_input_sats: int
    fee_sats: int
    change_sats: int
    estimated_vbytes: int
    waste_sats: int
    nodes_visited: int
    search_complete: bool


def _compact_size_length(value: int) -> int:
    if value < 0xFD:
        return 1
    if value <= 0xFFFF:
        return 3
    if value <= 0xFFFFFFFF:
        return 5
    return 9


def _serialized_output_size(script_pubkey: bytes) -> int:
    return 8 + _compact_size_length(len(script_pubkey)) + len(script_pubkey)


def _is_witness_program(script_pubkey: bytes) -> bool:
    if len(script_pubkey) < 4 or len(script_pubkey) > 42:
        return False
    version = script_pubkey[0]
    if version != 0 and not 0x51 <= version <= 0x60:
        return False
    return script_pubkey[1] == len(script_pubkey) - 2


def dust_threshold(script_pubkey: bytes, *, dust_relay_fee_sat_kvb: int = 3_000) -> int:
    """Compute Bitcoin Core's default dust threshold for a scriptPubKey.

    Core defines dust from serialized output size plus an estimated input spend
    size and the configured dust relay fee. Its default fee is 3000 sat/kvB;
    witness-program outputs use the standard SegWit-v0 P2WPKH spend estimate.
    """
    if not isinstance(script_pubkey, bytes):
        raise TypeError("script_pubkey must be bytes")
    if type(dust_relay_fee_sat_kvb) is not int or dust_relay_fee_sat_kvb < 0:
        raise ValueError("dust_relay_fee_sat_kvb must be a non-negative integer")
    if script_pubkey.startswith(b"\x6a"):
        return 0
    spend_size = 67 if _is_witness_program(script_pubkey) else 148
    total_size = _serialized_output_size(script_pubkey) + spend_size
    fee = dust_relay_fee_sat_kvb * total_size // 1_000
    return max(1, fee) if dust_relay_fee_sat_kvb else 0


def _fee(rate: Decimal, vbytes: int) -> int:
    return int((rate * vbytes).to_integral_value(rounding=ROUND_CEILING))


def _rate(value: Decimal | int | str) -> Decimal:
    if isinstance(value, (bool, float)):
        raise TypeError("fee_rate_sat_vb must be Decimal, int, or decimal string")
    try:
        result = value if isinstance(value, Decimal) else Decimal(value)
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("fee_rate_sat_vb is not a valid decimal") from exc
    if not result.is_finite() or result <= 0:
        raise ValueError("fee_rate_sat_vb must be finite and positive")
    return result


def _change_input_vbytes(script_pubkey: bytes) -> int:
    if len(script_pubkey) == 22 and script_pubkey[:2] == b"\x00\x14":
        return _MIN_WITNESS_INPUT_VBYTES
    if (
        len(script_pubkey) == 23
        and script_pubkey[:2] == b"\xa9\x14"
        and script_pubkey[-1:] == b"\x87"
    ):
        return _P2SH_P2WPKH_INPUT_VBYTES
    raise ValueError("change script must be P2WPKH or P2SH-P2WPKH")


def _selection_for_subset(
    utxos: tuple[UTXO, ...],
    total_sats: int,
    target_sats: int,
    fee_rate: Decimal,
    destination_script: bytes,
    change_script: bytes,
    max_fee_sats: int,
    dust_relay_fee_sat_kvb: int,
    nodes_visited: int,
    search_complete: bool,
) -> CoinSelection | None:
    if not utxos:
        return None
    input_vbytes = sum(utxo.input_vbytes for utxo in utxos)
    one_output_vbytes = _TX_OVERHEAD_VBYTES + input_vbytes + _serialized_output_size(destination_script)
    no_change_fee = _fee(fee_rate, one_output_vbytes)
    remainder = total_sats - target_sats - no_change_fee
    if remainder < 0:
        return None

    change_dust = dust_threshold(change_script, dust_relay_fee_sat_kvb=dust_relay_fee_sat_kvb)
    future_change_fee = _fee(fee_rate, _change_input_vbytes(change_script))
    change_output_fee = _fee(fee_rate, _serialized_output_size(change_script))
    economical_change_minimum = max(change_dust, future_change_fee + change_output_fee)

    if remainder < economical_change_minimum:
        actual_fee = total_sats - target_sats
        if actual_fee > max_fee_sats:
            return None
        return CoinSelection(
            utxos,
            total_sats,
            actual_fee,
            0,
            one_output_vbytes,
            actual_fee - no_change_fee,
            nodes_visited,
            search_complete,
        )

    two_output_vbytes = one_output_vbytes + _serialized_output_size(change_script)
    change_fee = _fee(fee_rate, two_output_vbytes)
    change_sats = total_sats - target_sats - change_fee
    if change_sats < change_dust or change_fee > max_fee_sats:
        return None
    waste = change_fee - no_change_fee + future_change_fee
    return CoinSelection(
        utxos,
        total_sats,
        change_fee,
        change_sats,
        two_output_vbytes,
        waste,
        nodes_visited,
        search_complete,
    )


def select_coins_bnb(
    available: Iterable[UTXO],
    target_sats: int,
    *,
    fee_rate_sat_vb: Decimal | int | str,
    destination_script_pubkey: bytes,
    change_script_pubkey: bytes,
    max_fee_sats: int,
    max_nodes: int = 100_000,
    dust_relay_fee_sat_kvb: int = _DEFAULT_DUST_RELAY_FEE_SAT_KVB,
) -> CoinSelection:
    """Find a low-waste subset using bounded depth-first Branch-and-Bound.

    The search explores include/exclude choices in descending effective-value
    order. It prefers low-waste no-change sets, accounting for the cost of a
    change output and its future spend. ``max_nodes`` is a visible work bound;
    ``search_complete`` is false if it was reached before all candidates were
    explored, so callers can refuse a partial best result when required.
    """
    if type(target_sats) is not int or target_sats <= 0:
        raise ValueError("target_sats must be a positive integer")
    if type(max_fee_sats) is not int or max_fee_sats < 0:
        raise ValueError("max_fee_sats must be a non-negative integer")
    if type(max_nodes) is not int or max_nodes < 1:
        raise ValueError("max_nodes must be a positive integer")
    if not isinstance(destination_script_pubkey, bytes) or not destination_script_pubkey:
        raise ValueError("destination_script_pubkey must be non-empty bytes")
    if not isinstance(change_script_pubkey, bytes) or not change_script_pubkey:
        raise ValueError("change_script_pubkey must be non-empty bytes")
    _change_input_vbytes(change_script_pubkey)
    fee_rate = _rate(fee_rate_sat_vb)

    candidates = tuple(
        sorted(
            (utxo for utxo in available if utxo.value_sats > 0),
            key=lambda coin: (-(coin.value_sats - _fee(fee_rate, coin.input_vbytes)), coin.txid, coin.vout),
        )
    )
    if not candidates:
        raise CoinSelectionError("no spendable UTXOs were supplied")
    if any(coin.input_vbytes not in {68, 91} for coin in candidates):
        raise CoinSelectionError("UTXO input weight is unsupported by the current signer")
    if any(coin.value_sats > 21_000_000 * 100_000_000 for coin in candidates):
        raise CoinSelectionError("UTXO value exceeds Bitcoin's maximum money supply")

    suffix_sums = [0] * (len(candidates) + 1)
    for index in range(len(candidates) - 1, -1, -1):
        suffix_sums[index] = suffix_sums[index + 1] + candidates[index].value_sats

    # Stack entries are the next candidate index, accumulated satoshis, and
    # immutable selected indices. Push exclusion first so inclusion is visited
    # first while preserving deterministic behavior.
    pending: list[tuple[int, int, tuple[int, ...]]] = [(0, 0, ())]
    best: CoinSelection | None = None
    nodes_visited = 0
    while pending and nodes_visited < max_nodes:
        index, total_sats, selected_indices = pending.pop()
        nodes_visited += 1
        selected = tuple(candidates[position] for position in selected_indices)
        candidate_result = _selection_for_subset(
            selected,
            total_sats,
            target_sats,
            fee_rate,
            destination_script_pubkey,
            change_script_pubkey,
            max_fee_sats,
            dust_relay_fee_sat_kvb,
            nodes_visited,
            search_complete=False,
        )
        if candidate_result is not None and (
            best is None
            or (candidate_result.waste_sats, len(candidate_result.utxos), candidate_result.total_input_sats)
            < (best.waste_sats, len(best.utxos), best.total_input_sats)
        ):
            best = candidate_result

        if index >= len(candidates) or total_sats + suffix_sums[index] < target_sats:
            continue
        pending.append((index + 1, total_sats, selected_indices))
        pending.append(
            (
                index + 1,
                total_sats + candidates[index].value_sats,
                selected_indices + (index,),
            )
        )

    search_complete = not pending
    if best is None:
        if not search_complete:
            raise CoinSelectionError("search budget exhausted without a feasible selection")
        raise CoinSelectionError("available UTXOs cannot cover target and estimated fees")
    return CoinSelection(
        best.utxos,
        best.total_input_sats,
        best.fee_sats,
        best.change_sats,
        best.estimated_vbytes,
        best.waste_sats,
        nodes_visited,
        search_complete,
    )


__all__ = ["CoinSelection", "CoinSelectionError", "dust_threshold", "select_coins_bnb"]
