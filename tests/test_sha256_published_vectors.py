"""Genuine published 19/20-step SHA-256 preimage witnesses verify against the reference.

These are third-party published vectors (srw repo); verifying them recomputes the
reduced-round digest from scratch and confirms KeyLab's step convention matches.
"""

from __future__ import annotations

import hashlib

import pytest

from keylab.hashes.reduced import sha256_reduced
from keylab.research.sha256_reduced import (
    PUBLISHED_VECTORS,
    SRW_ABC_19_STEP,
    SRW_ABC_20_STEP,
)

_ABC = hashlib.sha256(b"abc").digest()


@pytest.mark.parametrize("vector", PUBLISHED_VECTORS, ids=lambda v: v.name)
def test_published_vector_verifies(vector) -> None:
    assert len(vector.message) == 55  # a single padded block (55 bytes = 440 bits)
    assert vector.target == _ABC
    assert vector.verify()
    # Explicit, not just via .verify(), so the convention is pinned.
    assert sha256_reduced(vector.message, vector.rounds) == _ABC


def test_rounds_are_19_and_20() -> None:
    assert SRW_ABC_19_STEP.rounds == 19
    assert SRW_ABC_20_STEP.rounds == 20


def test_messages_are_distinct() -> None:
    assert SRW_ABC_19_STEP.message != SRW_ABC_20_STEP.message


def test_wrong_rounds_do_not_hit_target() -> None:
    # The 19-step witness is specific to 19 steps; a different step count misses.
    assert sha256_reduced(SRW_ABC_19_STEP.message, 18) != _ABC
    assert sha256_reduced(SRW_ABC_19_STEP.message, 20) != _ABC
