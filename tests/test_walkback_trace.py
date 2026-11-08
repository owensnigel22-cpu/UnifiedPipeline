"""Walkback-trace CLI (scripts/walkback_trace.py).

Verified against KNOWN scalars: the recovered k and reconstructed branch path are
checked against the planted k (the branches must be k's LSB-first bits and the
path must end at the identity). An independent scalar multiplication confirms the
public key, and the CLI's printed output is checked for the recovered value.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import walkback_trace

from keylab.ec.sec1 import serialize_sec1
from keylab.ec.secp256k1 import G, scalar_mult


@pytest.mark.parametrize("k,depth", [(5, 4), (6, 4), (11, 6), (13, 6)])
def test_trace_recovers_known_k_and_path(k, depth) -> None:
    point = scalar_mult(k, G)
    result = walkback_trace.trace(point, depth)
    assert result["found"] and result["k"] == k
    steps = result["steps"]
    # branches are k's LSB-first bits; the last step lands on the identity
    assert [s["branch"] for s in steps] == [(k >> i) & 1 for i in range(k.bit_length())]
    assert steps[-1]["x"] is None  # identity
    assert steps[-1]["bits"] == k


def test_cli_prints_recovered_scalar(capsys) -> None:
    k = 9
    pubkey = serialize_sec1(scalar_mult(k, G), compressed=True).hex()
    rc = walkback_trace.main([pubkey, "--depth", "6"])
    out = capsys.readouterr().out
    assert rc == 0
    assert f"Recovered k = {k}" in out
    assert "identity" in out  # the final step row


def test_cli_reports_not_found_when_depth_too_small(capsys) -> None:
    k = 200  # needs 8 bits
    pubkey = serialize_sec1(scalar_mult(k, G), compressed=True).hex()
    rc = walkback_trace.main([pubkey, "--depth", "4"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "No path to the identity" in out


def test_cli_rejects_bad_public_key(capsys) -> None:
    rc = walkback_trace.main(["not-hex-at-all", "--depth", "4"])
    assert rc == 2
    assert "invalid SEC1 public key" in capsys.readouterr().err
