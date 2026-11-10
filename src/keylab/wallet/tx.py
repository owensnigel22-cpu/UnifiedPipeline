"""Test-network PSBT payment preparation and structurally guarded broadcast.

This experimental wallet path supports only compressed-key P2WPKH and
P2SH-P2WPKH inputs produced by :mod:`keylab.wallet.utxo`. Mainnet broadcast is
rejected before any RPC request. Python key handling is not constant-time and
does not guarantee secret zeroization; use synthetic test funds only.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Protocol

from keylab.encoding.transaction import (
    Transaction,
    TxIn,
    TxOut,
    parse_transaction,
    serialize_transaction,
)
from keylab.psbt import extract, finalize, parse, serialize, sign
from keylab.psbt.model import (
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_IN_REDEEM_SCRIPT,
    PSBT_IN_WITNESS_UTXO,
    KeyPair,
    Psbt,
    PsbtMap,
)
from keylab.verify.node import Network
from keylab.wallet.coinselect import CoinSelection
from keylab.wallet.utxo import UTXO, btc_to_sats


class PaymentError(RuntimeError):
    """Raised when a payment cannot be safely prepared or broadcast."""


class WalletRPC(Protocol):
    def getblockchaininfo(self) -> dict[str, Any]: ...

    def gettxout(self, txid: str, vout: int, *, include_mempool: bool = True) -> dict[str, Any] | None: ...

    def testmempoolaccept(self, transactions: list[str]) -> list[dict[str, Any]]: ...

    def sendrawtransaction(
        self, raw_tx: str, *, network: Network, confirm_test_network: bool
    ) -> str: ...


class WIFProvider(Protocol):
    def get_wif(self, alias: str) -> str: ...


@dataclass(frozen=True)
class PreparedTransaction:
    """Fully signed and preflighted transaction, still not broadcast."""

    network: Network
    psbt: bytes
    raw_transaction: bytes
    txid: str
    selected_utxos: tuple[UTXO, ...]
    fee_sats: int


def _assert_test_network(network: Network) -> None:
    if not isinstance(network, Network):
        raise TypeError("network must be a Network value")
    if network is Network.MAINNET:
        raise RuntimeError("mainnet payments and broadcasts are disabled in M12")


def _assert_chain(client: WalletRPC, network: Network) -> None:
    info = client.getblockchaininfo()
    if info.get("chain") != network.rpc_chain:
        raise PaymentError("configured network does not match the connected Bitcoin Core node")


def _check_selected_outputs(client: WalletRPC, selected: tuple[UTXO, ...]) -> None:
    for utxo in selected:
        current = client.gettxout(utxo.txid, utxo.vout, include_mempool=True)
        if current is None:
            raise PaymentError(f"selected output {utxo.txid}:{utxo.vout} is no longer unspent")
        try:
            amount = current.get("value")
            if isinstance(amount, bool) or not isinstance(amount, (Decimal, int, str)):
                raise TypeError("node output value has an unsupported numeric type")
            value_sats = btc_to_sats(amount)
            script = current.get("scriptPubKey")
            script_hex = script.get("hex") if isinstance(script, dict) else None
            current_script = bytes.fromhex(script_hex) if isinstance(script_hex, str) else None
        except (TypeError, ValueError) as exc:
            raise PaymentError("node returned malformed selected-output data") from exc
        if value_sats != utxo.value_sats or current_script != utxo.script_pubkey:
            raise PaymentError(f"selected output {utxo.txid}:{utxo.vout} changed since scanning")


def _psbt_for_selection(
    selection: CoinSelection,
    destination_script_pubkey: bytes,
    change_script_pubkey: bytes,
    *,
    locktime: int,
) -> Psbt:
    if type(locktime) is not int or not 0 <= locktime <= 0xFFFFFFFF:
        raise ValueError("locktime must be a uint32")
    if not selection.utxos:
        raise PaymentError("coin selection has no inputs")
    if not selection.search_complete:
        raise PaymentError("refusing a coin selection whose bounded search was incomplete")
    if sum(item.value_sats for item in selection.utxos) != selection.total_input_sats:
        raise PaymentError("coin selection input total is inconsistent")
    if selection.total_input_sats != selection.target_sats + selection.fee_sats + selection.change_sats:
        raise PaymentError("coin selection amount accounting is inconsistent")

    outputs = [TxOut(selection.target_sats, destination_script_pubkey)]
    if selection.change_sats:
        outputs.append(TxOut(selection.change_sats, change_script_pubkey))
    inputs = tuple(
        TxIn(bytes.fromhex(utxo.txid)[::-1], utxo.vout, b"", 0xFFFFFFFD)
        for utxo in selection.utxos
    )
    unsigned_tx = Transaction(2, inputs, tuple(outputs), locktime)
    psbt = Psbt(
        PsbtMap([KeyPair(bytes([PSBT_GLOBAL_UNSIGNED_TX]), serialize_transaction(unsigned_tx))]),
        [],
        [PsbtMap() for _ in outputs],
    )
    for utxo in selection.utxos:
        if utxo.input_vbytes == 68 and utxo.redeem_script is not None:
            raise PaymentError("native P2WPKH input unexpectedly contains a redeem script")
        if utxo.input_vbytes == 91 and utxo.redeem_script is None:
            raise PaymentError("nested P2WPKH input is missing its redeem script")
        if utxo.input_vbytes not in {68, 91}:
            raise PaymentError("selected input type is not supported")
        witness_utxo = TxOut(utxo.value_sats, utxo.script_pubkey).serialize()
        records = [KeyPair(bytes([PSBT_IN_WITNESS_UTXO]), witness_utxo)]
        if utxo.redeem_script is not None:
            records.append(KeyPair(bytes([PSBT_IN_REDEEM_SCRIPT]), utxo.redeem_script))
        psbt.inputs.append(PsbtMap(records))
    return psbt


def _transaction_id(raw: bytes) -> str:
    tx = parse_transaction(raw)
    stripped_inputs = tuple(
        TxIn(item.prev_txid, item.prev_index, item.script_sig, item.sequence)
        for item in tx.inputs
    )
    stripped = serialize_transaction(Transaction(tx.version, stripped_inputs, tx.outputs, tx.locktime))
    return hashlib.sha256(hashlib.sha256(stripped).digest()).digest()[::-1].hex()


def prepare_payment(
    client: WalletRPC,
    network: Network,
    selection: CoinSelection,
    *,
    destination_script_pubkey: bytes,
    change_script_pubkey: bytes,
    key_alias: str,
    key_provider: WIFProvider,
    locktime: int = 0,
) -> PreparedTransaction:
    """Build, sign, finalize, and preflight a test-network payment without sending it."""
    _assert_test_network(network)
    _assert_chain(client, network)
    _check_selected_outputs(client, selection.utxos)
    unsigned = _psbt_for_selection(
        selection, destination_script_pubkey, change_script_pubkey, locktime=locktime
    )
    raw_wif = key_provider.get_wif(key_alias)
    from keylab.encoding.wif import decode as decode_wif

    private_bytes, compressed, wif_network = decode_wif(raw_wif)
    if wif_network != "testnet" or not compressed:
        raise PaymentError("wallet signing requires a compressed testnet/regtest WIF")
    signed = sign(unsigned, [int.from_bytes(private_bytes, "big")])
    finalized = finalize(signed)
    raw_transaction = extract(finalized)
    txid = _transaction_id(raw_transaction)
    raw_hex = raw_transaction.hex()
    result = client.testmempoolaccept([raw_hex])
    if len(result) != 1 or result[0].get("allowed") is not True:
        reason = result[0].get("reject-reason") if result else "malformed response"
        raise PaymentError(f"node rejected transaction during preflight: {reason}")
    return PreparedTransaction(
        network=network,
        psbt=serialize(finalized),
        raw_transaction=raw_transaction,
        txid=txid,
        selected_utxos=selection.utxos,
        fee_sats=selection.fee_sats,
    )


def broadcast_prepared(
    client: WalletRPC,
    prepared: PreparedTransaction,
    *,
    network: Network,
    confirm_test_network: bool,
) -> str:
    """Revalidate and submit once; MAINNET is rejected before RPC activity."""
    _assert_test_network(network)
    if type(confirm_test_network) is not bool or confirm_test_network is not True:
        raise RuntimeError("explicit test-network confirmation is required to broadcast")
    if prepared.network is not network:
        raise PaymentError("prepared transaction network does not match broadcast network")
    parsed_psbt = parse(prepared.psbt)
    extracted = extract(finalize(parsed_psbt))
    if extracted != prepared.raw_transaction or _transaction_id(extracted) != prepared.txid:
        raise PaymentError("prepared transaction bytes or transaction id do not match its PSBT")
    _assert_chain(client, network)
    _check_selected_outputs(client, prepared.selected_utxos)
    raw_hex = extracted.hex()
    result = client.testmempoolaccept([raw_hex])
    if len(result) != 1 or result[0].get("allowed") is not True:
        reason = result[0].get("reject-reason") if result else "malformed response"
        raise PaymentError(f"node rejected transaction during broadcast preflight: {reason}")
    txid = client.sendrawtransaction(
        raw_hex, network=network, confirm_test_network=confirm_test_network
    )
    if txid.lower() != prepared.txid:
        raise PaymentError("node returned a transaction id different from the prepared transaction")
    return txid.lower()


__all__ = ["PaymentError", "PreparedTransaction", "broadcast_prepared", "prepare_payment"]
