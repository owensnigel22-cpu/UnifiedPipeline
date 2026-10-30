"""BIP-327 MuSig2 key aggregation, key sorting, and aggregate-key tweaking.

This module implements the public-key side of BIP-327 (KeySort, KeyAgg,
KeyAgg coefficients, and plain/x-only ApplyTweak). It does not implement
nonce generation or partial signing: those steps hold secret state whose
misuse leaks keys, and an educational Python port is the wrong place for them.

Individual keys are 33-byte compressed "plain" public keys, exactly as the
BIP requires. A 32-byte x-only key is *not* accepted; earlier MuSig2 drafts
used x-only inputs, and that legacy behavior is kept separately in
``keylab.advanced_suite.musig2_aggregate_keys(..., mode="legacy-xonly")``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from keylab.ec.secp256k1 import (
    G,
    N,
    Point,
    compress_pubkey,
    decompress_pubkey,
    point_add_affine,
    scalar_mult,
)
from keylab.hashes.tagged import tagged_hash

_ABSENT_SECOND_KEY = b"\x00" * 33


class InvalidContributionError(ValueError):
    """Raised when one signer's contribution (here, a public key) is invalid.

    ``signer`` is the zero-based index of the offending key and ``contrib``
    names the invalid contribution, mirroring the BIP-327 reference.
    """

    def __init__(self, signer: int, contrib: str) -> None:
        super().__init__(f"invalid {contrib} from signer {signer}")
        self.signer = signer
        self.contrib = contrib


@dataclass(frozen=True)
class KeyAggContext:
    """BIP-327 KeyAgg context: aggregate point plus tweak accumulators."""

    point: tuple[int, int]
    gacc: int
    tacc: int

    @property
    def xonly(self) -> bytes:
        """The 32-byte x-only aggregate key (``GetXonlyPubkey``)."""
        return self.point[0].to_bytes(32, "big")

    @property
    def plain(self) -> bytes:
        """The 33-byte compressed aggregate key (``GetPlainPubkey``)."""
        return compress_pubkey(self.point)


def _check_plain_key(pubkey: bytes) -> bytes:
    if not isinstance(pubkey, (bytes, bytearray)):
        raise TypeError("public keys must be bytes")
    return bytes(pubkey)


def _cpoint(pubkey: bytes) -> tuple[int, int]:
    """Parse a 33-byte compressed key the way BIP-327's ``cpoint`` does."""
    if len(pubkey) != 33 or pubkey[0] not in (2, 3):
        raise ValueError("public key is not a valid compressed point")
    return decompress_pubkey(pubkey)


def key_sort(pubkeys: Sequence[bytes]) -> list[bytes]:
    """Sort plain public keys lexicographically (BIP-327 ``KeySort``)."""
    return sorted(_check_plain_key(pubkey) for pubkey in pubkeys)


def hash_keys(pubkeys: Sequence[bytes]) -> bytes:
    """Return ``hash_KeyAgg list(pk_1 || ... || pk_u)``."""
    return tagged_hash("KeyAgg list", b"".join(_check_plain_key(pk) for pk in pubkeys))


def get_second_key(pubkeys: Sequence[bytes]) -> bytes:
    """Return the first key that differs from ``pubkeys[0]``, or 33 zero bytes."""
    keys = [_check_plain_key(pk) for pk in pubkeys]
    for key in keys[1:]:
        if key != keys[0]:
            return key
    return _ABSENT_SECOND_KEY


def _key_agg_coeff_internal(list_hash: bytes, pubkey: bytes, second_key: bytes) -> int:
    if pubkey == second_key:
        return 1
    return int.from_bytes(tagged_hash("KeyAgg coefficient", list_hash + pubkey), "big") % N


def key_agg_coeff(pubkeys: Sequence[bytes], pubkey: bytes) -> int:
    """Return the KeyAgg coefficient ``a_i`` for ``pubkey`` within ``pubkeys``."""
    keys = [_check_plain_key(pk) for pk in pubkeys]
    return _key_agg_coeff_internal(hash_keys(keys), _check_plain_key(pubkey), get_second_key(keys))


def key_agg(pubkeys: Sequence[bytes]) -> KeyAggContext:
    """Aggregate plain public keys into a BIP-327 KeyAgg context.

    Raises :class:`InvalidContributionError` naming the first invalid key.
    The aggregation order matters; call :func:`key_sort` first for an
    order-independent aggregate key.
    """
    keys = [_check_plain_key(pk) for pk in pubkeys]
    if not keys:
        raise ValueError("at least one public key is required")
    list_hash = hash_keys(keys)
    second_key = get_second_key(keys)
    aggregate: Point = None
    for index, key in enumerate(keys):
        try:
            point = _cpoint(key)
        except ValueError as exc:
            raise InvalidContributionError(index, "pubkey") from exc
        coefficient = _key_agg_coeff_internal(list_hash, key, second_key)
        aggregate = point_add_affine(aggregate, scalar_mult(coefficient, point))
    if aggregate is None:
        # Negligible probability for honestly generated keys; BIP-327 asserts here.
        raise ArithmeticError("aggregate public key is the point at infinity")
    return KeyAggContext(aggregate, 1, 0)


def apply_tweak(context: KeyAggContext, tweak: bytes, is_xonly: bool) -> KeyAggContext:
    """Apply a plain or x-only tweak to a KeyAgg context (BIP-327 ``ApplyTweak``)."""
    if not isinstance(tweak, (bytes, bytearray)) or len(tweak) != 32:
        raise ValueError("The tweak must be a 32-byte array.")
    point, gacc, tacc = context.point, context.gacc, context.tacc
    sign = N - 1 if is_xonly and point[1] % 2 else 1
    tweak_scalar = int.from_bytes(tweak, "big")
    if tweak_scalar >= N:
        raise ValueError("The tweak must be less than n.")
    tweaked = point_add_affine(scalar_mult(sign, point), scalar_mult(tweak_scalar, G))
    if tweaked is None:
        raise ValueError("The result of tweaking cannot be infinity.")
    return KeyAggContext(tweaked, sign * gacc % N, (tweak_scalar + sign * tacc) % N)


def key_agg_and_tweak(
    pubkeys: Sequence[bytes], tweaks: Sequence[bytes] = (), is_xonly: Sequence[bool] = ()
) -> KeyAggContext:
    """Aggregate keys, then apply each tweak in order."""
    if len(tweaks) != len(is_xonly):
        raise ValueError("tweaks and is_xonly must have the same length")
    context = key_agg(pubkeys)
    for tweak, xonly in zip(tweaks, is_xonly):
        context = apply_tweak(context, tweak, xonly)
    return context


__all__ = [
    "InvalidContributionError",
    "KeyAggContext",
    "apply_tweak",
    "get_second_key",
    "hash_keys",
    "key_agg",
    "key_agg_and_tweak",
    "key_agg_coeff",
    "key_sort",
]
