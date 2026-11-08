"""Recover an ECDSA private key from biased (short) nonces via the Hidden Number Problem.

Mathematical role: for each ECDSA signature ``(r_i, s_i)`` over ``z_i``,
``k_i = s_i^-1 z_i + (s_i^-1 r_i) d (mod order)``. If every nonce is biased so that
``0 <= k_i < 2**nonce_bits`` (known high bits zero), then with ``d`` the hidden
number this is a Hidden Number Problem: ``obs_i = 2**(nonce_bits-1) - s_i^-1 z_i``
approximates ``(s_i^-1 r_i) d`` to within the centred nonce. It is solved with a
**scaled** CVP lattice (the modular coordinates are weighted by ``order/2**nonce_bits``
so a large ``d`` is not penalised -- the toy lattice in
:mod:`keylab.research.hnp_lattice` only recovers a *small* hidden number) reduced
with that module's LLL/Babai.

Scope boundary: the leakage model (``nonce_bits``) is explicit and required; this
recovers ``d`` only from genuinely biased nonces, and reports "insufficient"
(never a false positive) when too few signatures are supplied. Correct,
uniform-nonce ECDSA yields nothing. ``order`` defaults to secp256k1's ``N``; the
exact-rational LLL is impractically slow at that width (see SEC_STATE_JOURNAL.md
-- recovery is demonstrated at reduced ``order`` where it is fast). See SECURITY.md.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from keylab.ec.secp256k1 import G, N, Point, scalar_mult
from keylab.research.hnp_lattice import _babai_nearest_plane, _lll_reduce

__all__ = ["HNPResult", "recover_hidden_number", "recover_private_key_from_biased_nonces"]


@dataclass(frozen=True)
class HNPResult:
    """Outcome of an HNP recovery attempt."""

    recovered: int | None
    sufficient: bool
    signatures_used: int
    nonce_bits: int


def _min_signatures(order_bits: int, nonce_bits: int) -> int:
    leaked = order_bits - nonce_bits
    if leaked <= 0:
        return 1_000_000
    return order_bits // leaked + 3


def recover_hidden_number(
    multipliers: Sequence[int], observations: Sequence[int], *, modulus: int, nonce_bits: int
) -> int | None:
    """Core HNP: recover ``x`` from ``obs_i = mult_i*x + e_i (mod modulus)``, ``|e_i| < 2**(nonce_bits-1)``.

    Uses a scaled CVP lattice so a hidden number of full width is recovered, not
    just a small one. Returns ``x`` in ``[0, modulus)`` (caller verifies it).
    """
    m = len(multipliers)
    scale = max(1, modulus >> (nonce_bits - 1))  # weight modular coords ~ modulus / error-bound
    basis = [[scale * modulus * int(i == j) for j in range(m)] + [0] for i in range(m)]
    basis.append([scale * t for t in multipliers] + [1])
    target = [scale * o for o in observations] + [0]
    reduced = _lll_reduce(basis)
    nearby = _babai_nearest_plane(reduced, target)
    return nearby[-1] % modulus


def recover_private_key_from_biased_nonces(
    signatures: Sequence[tuple[int, int, int]],
    *,
    nonce_bits: int,
    order: int = N,
    public_key: Point | None = None,
) -> HNPResult:
    """Recover ``d`` from biased-nonce ECDSA signatures ``(r, s, z)`` modulo ``order``.

    ``nonce_bits`` is the stated leakage model (every nonce ``< 2**nonce_bits``).
    Returns an :class:`HNPResult`; ``recovered`` is ``None`` with
    ``sufficient=False`` when too few signatures are supplied, and ``None`` with
    ``sufficient=True`` when the lattice ran but the result failed the optional
    forward check (``scalar_mult(d, G) == public_key``, only meaningful for the
    default ``order == N``) -- never a wrong key.
    """
    if type(order) is not int or order < 3:
        raise ValueError("order must be an int >= 3")
    if type(nonce_bits) is not int or not 1 <= nonce_bits < order.bit_length():
        raise ValueError("nonce_bits must be an int in [1, order.bit_length()-1]")
    m = len(signatures)
    if m < _min_signatures(order.bit_length(), nonce_bits):
        return HNPResult(None, False, m, nonce_bits)

    half = 1 << (nonce_bits - 1)
    multipliers: list[int] = []
    observations: list[int] = []
    for r, s, z in signatures:
        if not (1 <= r < order and 1 <= s < order):
            raise ValueError("each signature needs r, s in [1, order-1]")
        s_inv = pow(s, -1, order)
        multipliers.append(s_inv * r % order)
        observations.append((half - s_inv * z) % order)

    d = recover_hidden_number(multipliers, observations, modulus=order, nonce_bits=nonce_bits)
    if d is None or d == 0:
        return HNPResult(None, True, m, nonce_bits)
    if order == N and public_key is not None and scalar_mult(d, G) != public_key:
        return HNPResult(None, True, m, nonce_bits)
    return HNPResult(d, True, m, nonce_bits)
