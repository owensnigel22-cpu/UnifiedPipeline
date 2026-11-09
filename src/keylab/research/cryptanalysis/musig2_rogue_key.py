"""Educational rogue-key demonstration using the repository's BIP-327 KeyAgg."""

from __future__ import annotations

from dataclasses import dataclass

from keylab.ec.musig2 import KeyAggContext, key_agg, key_agg_coeff
from keylab.ec.secp256k1 import (
    G,
    N,
    compress_pubkey,
    point_add_affine,
    point_negate_affine,
    scalar_mult,
)


@dataclass(frozen=True)
class RogueKeyDemonstration:
    """Public results showing naive aggregation versus BIP-327 KeyAgg."""

    naive_aggregate: tuple[int, int]
    rogue_target: tuple[int, int]
    musig2_context: KeyAggContext
    naive_attack_succeeds: bool
    musig2_aggregate_matches_target_xonly: bool
    key_agg_coefficients: tuple[int, int]


def demonstrate_rogue_key_resistance(
    honest_secret: int,
    attacker_target_secret: int,
) -> RogueKeyDemonstration:
    """Show the classic two-key rogue-key attack and BIP-327's defense.

    The attacker chooses ``P_rogue = d_rogue*G`` and, after observing the honest
    key ``P_1``, submits ``P_2 = P_rogue - P_1``. Naive addition gives
    ``P_1 + P_2 = P_rogue`` so the attacker knows the aggregate discrete log.
    BIP-327 KeyAgg instead hashes the complete ordered key list and each key to
    derive coefficients (with its specified coefficient-one optimization).
    The demo reports whether the resulting x-only aggregate still equals the
    attacker's target.

    BIP-327 KeyAgg itself does not use a key commit/reveal round: the protection
    here is coefficient-based, as specified by BIP-327. This function only
    demonstrates key aggregation; it does not implement MuSig2 nonces or signing.
    """
    for name, secret in (
        ("honest_secret", honest_secret),
        ("attacker_target_secret", attacker_target_secret),
    ):
        if type(secret) is not int or not 1 <= secret < N:
            raise ValueError(f"{name} must be an integer in [1, N-1]")

    honest_point = scalar_mult(honest_secret, G)
    rogue_target = scalar_mult(attacker_target_secret, G)
    if honest_point is None or rogue_target is None:
        raise ValueError("chosen secrets must produce finite public points")
    rogue_key = point_add_affine(rogue_target, point_negate_affine(honest_point))
    if rogue_key is None:
        raise ValueError("chosen secrets produce an invalid point-at-infinity rogue key")

    honest_bytes = compress_pubkey(honest_point)
    rogue_bytes = compress_pubkey(rogue_key)
    naive_aggregate = point_add_affine(honest_point, rogue_key)
    assert naive_aggregate is not None

    context = key_agg([honest_bytes, rogue_bytes])
    coefficients = (
        key_agg_coeff([honest_bytes, rogue_bytes], honest_bytes),
        key_agg_coeff([honest_bytes, rogue_bytes], rogue_bytes),
    )
    return RogueKeyDemonstration(
        naive_aggregate=naive_aggregate,
        rogue_target=rogue_target,
        musig2_context=context,
        naive_attack_succeeds=naive_aggregate == rogue_target,
        musig2_aggregate_matches_target_xonly=context.xonly == rogue_target[0].to_bytes(32, "big"),
        key_agg_coefficients=coefficients,
    )

__all__ = ["RogueKeyDemonstration", "demonstrate_rogue_key_resistance"]
