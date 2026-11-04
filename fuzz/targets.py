"""Shared fuzz-target bodies for KeyLab's untrusted-input parsers.

Each ``run_<name>(data: bytes)`` is a pure, deterministic function (no time,
randomness, or environment branching) that feeds ``data`` to one parser and
swallows only that parser's *documented* exceptions. Any other exception
propagates so the fuzzer records it as a finding.

These bodies are the single source of truth: the Atheris entry points
(``fuzz/fuzz_*.py``) and the non-Atheris corpus smoke test
(``tests/test_corpus_smoke.py``) both call them, so the two paths cannot
diverge. Cheap structural "prefix" filters (grammar-lite) short-circuit inputs
that could not reach the interesting states, so a coverage-guided campaign does
not burn its budget in the shallow rejection path.
"""

from __future__ import annotations

from keylab import mnemonic as _mn
from keylab import psbt as _psbt
from keylab.encoding import base58 as _base58
from keylab.encoding import bech32 as _bech32
from keylab.encoding import transaction as _tx
from keylab.encoding import wif as _wif

_PSBT_MAGIC = b"psbt\xff"
_WIF_FIRST = frozenset("5KL9c")  # mainnet 5/K/L, testnet 9/c


def _text(data: bytes) -> str:
    # surrogateescape is total (never raises) for arbitrary fuzz bytes, so a raw
    # byte like 0xff becomes a non-charset character the decoder rejects as a
    # normal ValueError rather than a spurious UnicodeDecodeError "finding".
    return data.decode("utf-8", "surrogateescape")


def run_psbt(data: bytes) -> None:
    if not data.startswith(_PSBT_MAGIC):  # grammar-lite: require the PSBT magic
        return
    try:
        _psbt.parse(data)
    except (_psbt.PsbtError, ValueError):
        return


def run_transaction(data: bytes) -> None:
    try:
        _tx.parse_transaction(data)
    except ValueError:
        return


def run_bech32(data: bytes) -> None:
    text = _text(data)
    sep = text.rfind("1")  # grammar-lite: non-empty HRP + separator + data
    if sep <= 0 or sep == len(text) - 1:
        return
    try:
        _bech32.decode(text)
    except ValueError:
        pass
    try:
        _bech32.decode_segwit_address(text)
    except ValueError:
        return


def run_base58(data: bytes) -> None:
    text = _text(data)
    if not text:
        return
    try:
        _base58.b58decode(text)
    except ValueError:
        pass
    try:
        _base58.check_decode(text)
    except ValueError:
        return


def run_wif(data: bytes) -> None:
    text = _text(data)
    if not text or text[0] not in _WIF_FIRST:  # grammar-lite: WIF version prefix
        return
    try:
        _wif.decode(text)
    except ValueError:
        return


def run_mnemonic(data: bytes) -> None:
    text = _text(data)
    first = text.split(" ", 1)[0] if text else ""
    if first not in _mn.ENGLISH_WORDLIST:  # grammar-lite: first word must be real
        return
    try:
        _mn.mnemonic_to_entropy(text)
    except ValueError:
        pass
    _mn.is_valid_mnemonic(text)


TARGETS = {
    "psbt": run_psbt,
    "transaction": run_transaction,
    "bech32": run_bech32,
    "base58": run_base58,
    "wif": run_wif,
    "mnemonic": run_mnemonic,
}
