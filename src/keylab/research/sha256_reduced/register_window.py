"""Deterministic reduced-round SHA-256 compression preimages via the a-register window.

For a round count ``r`` with ``8 <= r <= 16`` the SHA-256 message schedule is not
yet extended (no ``W_16..``), so the compression function is *algebraically
invertible*: the output registers are a sliding window of the ``a``- and
``e``-sequences, and choosing that sequence fixes every message word in closed
form. This module turns a target compression output into a 64-byte block that
reproduces it, deterministically and forward-verified — the "context shaping"
idea (shape the register window, read off the message) at the round counts where
it needs no search.

This is a **compression-function** preimage (the block's words are free). It does
not attack the padded hash, and it stops at 16 rounds: at 17+ rounds the schedule
feeds ``W_16..`` back in and the system stops being triangular (see
:mod:`keylab.research.sha256_reduced.context_shaping` for the 19-step search that
handles that coupling). Nothing here bears on full 64-round SHA-256.

The construction is the ``E``/``Wt`` identity ported from ``srw/sha256-19-and-20-
step-preimages-with-padding`` (MIT); see ``docs/references.md``.
"""

from __future__ import annotations

from dataclasses import dataclass

from keylab.hashes.reduced import _SHA_IV, _SHA_K, _sha_compress

_MASK = 0xFFFFFFFF
_IV_BYTES = b"".join(value.to_bytes(4, "big") for value in _SHA_IV)
_MIN_ROUNDS = 8
_MAX_ROUNDS = 16


def _ror(value: int, count: int) -> int:
    count &= 31
    return ((value >> count) | (value << ((-count) & 31))) & _MASK


def _big_sigma0(x: int) -> int:
    return _ror(x, 2) ^ _ror(x, 13) ^ _ror(x, 22)


def _big_sigma1(x: int) -> int:
    return _ror(x, 6) ^ _ror(x, 11) ^ _ror(x, 25)


def _maj(a: int, b: int, c: int) -> int:
    return (a & b) ^ (a & c) ^ (b & c)


def _ch(e: int, f: int, g: int) -> int:
    return (e & f) ^ (~e & g & _MASK)


@dataclass(frozen=True)
class CompressionPreimage:
    """A 64-byte block whose reduced-round compression equals ``target``."""

    block: bytes
    rounds: int
    target: bytes
    initial_state: bytes
    verified: bool


def reduced_compress(block: bytes, rounds: int, *, initial_state: bytes = _IV_BYTES) -> bytes:
    """Return the ``rounds``-round SHA-256 compression of one 64-byte ``block``.

    This is the raw compression with feed-forward (no padding), i.e. the quantity
    the register-window preimage targets.
    """
    if len(block) != 64:
        raise ValueError("block must be exactly 64 bytes")
    if len(initial_state) != 32:
        raise ValueError("initial_state must be exactly 32 bytes")
    if not 1 <= rounds <= 64:
        raise ValueError("rounds must be between 1 and 64")
    state = tuple(int.from_bytes(initial_state[i : i + 4], "big") for i in range(0, 32, 4))
    out = _sha_compress(block, state, rounds)
    return b"".join(word.to_bytes(4, "big") for word in out)


def register_window_preimage(
    target_digest: bytes,
    *,
    rounds: int,
    initial_state: bytes = _IV_BYTES,
    free_fill: int = 0,
) -> CompressionPreimage:
    """Construct a 64-byte block whose ``rounds``-round compression is ``target_digest``.

    Supported for ``8 <= rounds <= 16``. ``free_fill`` (a 32-bit value) seeds the
    unconstrained middle of the ``a``-sequence, so distinct values yield distinct
    preimages of the same target. The result is **forward-verified** against
    :func:`reduced_compress` before it is returned; a mismatch raises
    ``RuntimeError`` (it should never happen and would indicate a bug).
    """
    if len(target_digest) != 32:
        raise ValueError("target_digest must be exactly 32 bytes")
    if len(initial_state) != 32:
        raise ValueError("initial_state must be exactly 32 bytes")
    if not _MIN_ROUNDS <= rounds <= _MAX_ROUNDS:
        raise ValueError(
            f"register_window_preimage supports {_MIN_ROUNDS}..{_MAX_ROUNDS} rounds "
            "(at 17+ rounds the message schedule couples; use context_shaping)"
        )
    if type(free_fill) is not int or not 0 <= free_fill <= _MASK:
        raise ValueError("free_fill must be a 32-bit unsigned integer")

    iv = tuple(int.from_bytes(initial_state[i : i + 4], "big") for i in range(0, 32, 4))
    target = tuple(int.from_bytes(target_digest[i : i + 4], "big") for i in range(0, 32, 4))

    # a[t] / e[t] indexed by step t in [-3, rounds]; history comes from the IV.
    a: dict[int, int] = {-3: iv[3], -2: iv[2], -1: iv[1], 0: iv[0]}
    e: dict[int, int] = {-3: iv[7], -2: iv[6], -1: iv[5], 0: iv[4]}

    # Undo feed-forward: the register window equals (target - IV) per word.
    a_window = tuple((target[i] - iv[i]) & _MASK for i in range(4))
    e_window = tuple((target[4 + i] - iv[4 + i]) & _MASK for i in range(4))

    for step in range(1, rounds - 7):
        a[step] = free_fill
    # Top four a-values come straight from the target a-window.
    a[rounds] = a_window[0]
    a[rounds - 1] = a_window[1]
    a[rounds - 2] = a_window[2]
    a[rounds - 3] = a_window[3]
    # Next four are pinned by the target e-window (e_{t+1} depends on a_{t-3..t+1}).
    for offset in range(4):
        top = rounds - offset
        a[rounds - 4 - offset] = (
            e_window[offset]
            - a[top]
            + _big_sigma0(a[top - 1])
            + _maj(a[top - 1], a[top - 2], a[top - 3])
        ) & _MASK

    # Derive the e-sequence, then each message word in closed form.
    for step in range(1, rounds + 1):
        e[step] = (
            a[step]
            - _big_sigma0(a[step - 1])
            - _maj(a[step - 1], a[step - 2], a[step - 3])
            + a[step - 4]
        ) & _MASK

    words: list[int] = []
    for step in range(rounds):
        word = (
            (e[step + 1] - a[step - 3])
            - e[step - 3]
            - _big_sigma1(e[step])
            - _ch(e[step], e[step - 1], e[step - 2])
            - _SHA_K[step]
        ) & _MASK
        words.append(word)
    words.extend([0] * (16 - len(words)))
    block = b"".join(word.to_bytes(4, "big") for word in words)

    verified = reduced_compress(block, rounds, initial_state=initial_state) == target_digest
    if not verified:
        raise RuntimeError("register_window_preimage failed self-verification (internal bug)")
    return CompressionPreimage(block, rounds, target_digest, initial_state, verified=True)


__all__ = [
    "CompressionPreimage",
    "reduced_compress",
    "register_window_preimage",
]
