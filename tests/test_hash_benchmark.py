"""Smoke test for the truncated-preimage benchmark harness core (scripts/benchmark_hash_preimage.py)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import benchmark_hash_preimage as bench


def test_search_once_returns_forward_verified_result() -> None:
    tries, wall = bench.search_once(12)
    assert tries > 0 and wall >= 0.0  # search_once asserts the digest prefix internally


def test_wall_statement_names_the_2_256_wall() -> None:
    s = bench._wall_statement(1e12)
    assert "2**256" in s and "EXTRAPOLATION" in s and "years" in s
