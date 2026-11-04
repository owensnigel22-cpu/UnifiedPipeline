"""BIP-174 Combiner role: merge PSBTs that describe the same unsigned transaction.

Given two or more structurally valid PSBTs with a byte-identical unsigned
transaction, this module returns a new PSBT whose global map and each input and
output map hold the *union* of the corresponding maps' key-value pairs. The
classic use is collecting partial signatures from independent signers before
finalization.

Merge semantics (BIP-174):

- identical ``PSBT_GLOBAL_UNSIGNED_TX`` across all inputs is required;
- key-value pairs are unioned per map, preserving first-seen order;
- the same key with the same value is kept once (deduplicated);
- the same key with *different* values keeps the first value seen (stable,
  input-order precedence); in ``strict`` mode a conflict on a finalized field
  (``0x07`` / ``0x08``) is rejected instead;
- unknown and proprietary keys are preserved.

The combiner performs no cryptography: it neither signs, finalizes, extracts,
nor interprets any value. It never mutates its inputs. It is the BIP-174 v0
Combiner only (same unsigned transaction) -- not a BIP-370 "merge" of differing
transactions. See SECURITY.md.
"""

from __future__ import annotations

from collections.abc import Iterable

from keylab.psbt.model import (
    PSBT_IN_FINAL_SCRIPTSIG,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    KeyPair,
    Psbt,
    PsbtError,
    PsbtMap,
)
from keylab.psbt.validator import validate

# Input fields where two different values are a semantic conflict, not a choice.
_INPUT_CRITICAL = frozenset({PSBT_IN_FINAL_SCRIPTSIG, PSBT_IN_FINAL_SCRIPTWITNESS})


class PsbtCombineError(PsbtError):
    """Raised when PSBTs cannot be combined (a subclass of :class:`PsbtError`)."""


def _union_maps(maps: list[PsbtMap], scope: str, critical: frozenset[int], *, strict: bool) -> PsbtMap:
    """Union several maps into one, applying the BIP-174 dedup / first-value rules."""
    chosen: dict[bytes, bytes] = {}
    order: list[bytes] = []
    for psbt_map in maps:
        for pair in psbt_map.pairs:
            if pair.key not in chosen:
                chosen[pair.key] = pair.value
                order.append(pair.key)
            elif chosen[pair.key] != pair.value:
                if strict and pair.key_type in critical:
                    raise PsbtCombineError(
                        f"conflicting values for {scope} key {pair.key.hex()} (finalized field)"
                    )
                # otherwise BIP-174 first-value rule: keep the value already chosen
    return PsbtMap([KeyPair(key, chosen[key]) for key in order])


def combine(psbts: Iterable[Psbt], *, strict: bool = True) -> Psbt:
    """Combine PSBTs that share one unsigned transaction into their union.

    Every PSBT must be structurally valid and carry a byte-identical unsigned
    transaction (and therefore matching input/output counts). Raises
    :class:`PsbtCombineError` otherwise. The inputs are never mutated.
    """
    psbt_list = list(psbts)
    if not psbt_list:
        raise PsbtCombineError("combine requires at least one PSBT")
    for psbt in psbt_list:
        validate(psbt)

    first = psbt_list[0]
    tx_bytes = first.unsigned_tx_bytes  # validate() guarantees this is present and parses
    for other in psbt_list[1:]:
        if other.unsigned_tx_bytes != tx_bytes:
            raise PsbtCombineError("all PSBTs must share the same unsigned transaction")
        if len(other.inputs) != len(first.inputs) or len(other.outputs) != len(first.outputs):
            raise PsbtCombineError("input/output map counts differ between PSBTs")

    global_map = _union_maps([p.global_map for p in psbt_list], "global", frozenset(), strict=strict)
    inputs = [
        _union_maps([p.inputs[i] for p in psbt_list], f"input {i}", _INPUT_CRITICAL, strict=strict)
        for i in range(len(first.inputs))
    ]
    outputs = [
        _union_maps([p.outputs[i] for p in psbt_list], f"output {i}", frozenset(), strict=strict)
        for i in range(len(first.outputs))
    ]
    result = Psbt(global_map, inputs, outputs)
    validate(result)
    return result


__all__ = [
    "PsbtCombineError",
    "combine",
]
