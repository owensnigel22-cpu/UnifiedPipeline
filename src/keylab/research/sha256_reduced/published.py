"""Published reduced-round SHA-256 preimage witnesses from the reference repos.

These are **genuine published vectors** from
``srw/sha256-19-and-20-step-preimages-with-padding`` (MIT): 55-byte messages whose
19-step and 20-step reduced SHA-256 digests both equal the standard 64-step
SHA-256 digest of ``b"abc"``. They are reproduced here to validate KeyLab's
reduced-round reference (:func:`keylab.hashes.reduced.sha256_reduced`) against an
independent third-party result, and to anchor the step convention.

Verifying a vector recomputes the reduced digest from scratch; it does not search.
See ``docs/references.md`` for attribution.
"""

from __future__ import annotations

from dataclasses import dataclass

from keylab.hashes.reduced import sha256_reduced

# SHA-256("abc"), the 64-step digest that both reduced-round messages must hit.
_ABC_TARGET = bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


@dataclass(frozen=True)
class PublishedPreimage:
    """A published reduced-round preimage witness (message -> reduced digest)."""

    name: str
    rounds: int
    message: bytes
    target: bytes
    source: str

    def verify(self) -> bool:
        """Recompute the reduced digest and compare to the published target."""
        return sha256_reduced(self.message, self.rounds) == self.target


_SRW = "srw/sha256-19-and-20-step-preimages-with-padding"

SRW_ABC_19_STEP = PublishedPreimage(
    name="srw-abc-19step",
    rounds=19,
    message=bytes.fromhex(
        "8ca254f8d04dd3fb04efaad6b1867588ffe833de49a144fedbf1839422892dc9"
        "f5a9158d8fc063290a14a9a6c55dfa245642a0247ec45a"
    ),
    target=_ABC_TARGET,
    source=_SRW,
)

SRW_ABC_20_STEP = PublishedPreimage(
    name="srw-abc-20step",
    rounds=20,
    message=bytes.fromhex(
        "edf6e70a7001ae71b900f18119aaa1fdf6c1179b4268891262a9539be04d4123"
        "6685e0c102e0ad23165e8b7157669819302ddcb3c68226"
    ),
    target=_ABC_TARGET,
    source=_SRW,
)

PUBLISHED_VECTORS: tuple[PublishedPreimage, ...] = (SRW_ABC_19_STEP, SRW_ABC_20_STEP)


__all__ = [
    "PUBLISHED_VECTORS",
    "SRW_ABC_19_STEP",
    "SRW_ABC_20_STEP",
    "PublishedPreimage",
]
