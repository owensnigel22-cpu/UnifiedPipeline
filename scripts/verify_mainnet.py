"""Fetch and locally verify SegWit-v0 transaction signatures via a public explorer."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import httpx

from keylab.encoding.transaction import TxOut
from keylab.verify import DEFAULT_ALLOWLIST, ReadOnlyExplorerClient, verify_transaction_signatures


def _load_prevouts(source: str) -> tuple[TxOut, ...]:
    text = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, dict) or not isinstance(data.get("prevouts"), list):
        raise TypeError('JSON must be an object with a "prevouts" array')

    prevouts: list[TxOut] = []
    for index, item in enumerate(data["prevouts"]):
        if not isinstance(item, dict):
            raise TypeError(f"prevouts[{index}] must be an object")
        amount = item.get("amount_sat")
        script_hex = item.get("script_pubkey")
        if type(amount) is not int or not 0 <= amount < (1 << 64):
            raise ValueError(f"prevouts[{index}].amount_sat must be an unsigned 64-bit integer")
        if not isinstance(script_hex, str) or re.fullmatch(r"(?:[0-9a-fA-F]{2})*", script_hex) is None:
            raise ValueError(f"prevouts[{index}].script_pubkey must be an even-length hex string")
        prevouts.append(TxOut(amount=amount, script_pubkey=bytes.fromhex(script_hex)))
    return tuple(prevouts)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch a transaction and verify supported BIP-143 signatures locally."
    )
    parser.add_argument("--txid", required=True, help="64-character transaction ID")
    parser.add_argument(
        "--prevout-data",
        required=True,
        metavar="JSON_FILE|-",
        help="JSON file containing one authenticated prevout per input, or - to read stdin",
    )
    parser.add_argument(
        "--explorer",
        default=DEFAULT_ALLOWLIST[0],
        help=f"allow-listed HTTPS explorer base URL (default: {DEFAULT_ALLOWLIST[0]})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        prevouts = _load_prevouts(args.prevout_data)
        with ReadOnlyExplorerClient(allowlist=(args.explorer,)) as client:
            raw_transaction = client.get_transaction_hex(args.txid)
        valid = verify_transaction_signatures(raw_transaction, prevouts)
    except (OSError, ValueError, httpx.HTTPError) as exc:
        print(f"FAIL: unable to verify transaction: {exc}", file=sys.stderr)
        return 2

    if not valid:
        print("FAIL: one or more inputs have an unsupported or invalid BIP-143 signature.")
        return 1

    print("PASS: all supported BIP-143 input signatures verify locally.")
    print("Note: prevout data must be independently authenticated; this is not consensus validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())