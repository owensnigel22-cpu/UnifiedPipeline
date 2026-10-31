"""Regression tests for BIP-341 control-block length and leaf-version constraints."""

from __future__ import annotations

import pytest

from keylab.ec.secp256k1 import G, P
from keylab.encoding.taproot import (
    TAPROOT_ANNEX_TAG,
    TAPROOT_CONTROL_MAX_NODE_COUNT,
    TapLeaf,
    tapbranch_hash,
    tapleaf_hash,
    taproot_control_block,
    taproot_output,
    verify_taproot_script_path,
)

INTERNAL = G[0].to_bytes(32, "big")
SCRIPT = b"\x51"


def _commitment(node_count: int, leaf_version: int = 0xC0) -> tuple[bytes, bytes]:
    """Build an output key and a control block whose Merkle path has ``node_count`` nodes."""
    path = [bytes([(i % 255) + 1]) * 32 for i in range(node_count)]
    root = tapleaf_hash(SCRIPT, leaf_version)
    for node in path:
        root = tapbranch_hash(root, node)
    output = taproot_output(INTERNAL, root)
    control = bytes([leaf_version | output.output_key_parity]) + INTERNAL + b"".join(path)
    return output.output_key_x, control


@pytest.mark.parametrize("node_count", [0, 1, 127, TAPROOT_CONTROL_MAX_NODE_COUNT])
def test_control_blocks_up_to_128_nodes_verify(node_count: int) -> None:
    output_key, control = _commitment(node_count)
    assert len(control) == 33 + 32 * node_count
    assert verify_taproot_script_path(output_key, SCRIPT, control)


@pytest.mark.parametrize("node_count", [TAPROOT_CONTROL_MAX_NODE_COUNT + 1, 200])
def test_control_blocks_longer_than_128_nodes_fail_even_when_the_commitment_matches(node_count: int) -> None:
    # Regression: a 129-node path used to verify because only the length modulus was checked.
    output_key, control = _commitment(node_count)
    assert not verify_taproot_script_path(output_key, SCRIPT, control)


@pytest.mark.parametrize("extra", [1, 31, 33])
def test_control_blocks_with_partial_nodes_fail(extra: int) -> None:
    output_key, control = _commitment(1)
    assert not verify_taproot_script_path(output_key, SCRIPT, control + bytes(extra))
    assert not verify_taproot_script_path(output_key, SCRIPT, control[:32])


def test_control_block_serializer_enforces_the_same_limit() -> None:
    with pytest.raises(ValueError):
        taproot_control_block(INTERNAL, 0, [bytes(32)] * (TAPROOT_CONTROL_MAX_NODE_COUNT + 1))
    assert len(taproot_control_block(INTERNAL, 0, [bytes(32)] * TAPROOT_CONTROL_MAX_NODE_COUNT)) == 33 + 32 * 128


def test_leaf_version_0x50_is_rejected_everywhere() -> None:
    assert TAPROOT_ANNEX_TAG == 0x50
    with pytest.raises(ValueError, match="annex"):
        tapleaf_hash(SCRIPT, 0x50)
    with pytest.raises(ValueError, match="annex"):
        _ = TapLeaf(SCRIPT, 0x50).leaf_hash
    with pytest.raises(ValueError, match="annex"):
        taproot_control_block(INTERNAL, 0, leaf_version=0x50)
    # A control block that claims leaf version 0x50 never verifies.
    output_key, control = _commitment(0)
    forged = bytes([0x50 | (control[0] & 1)]) + control[1:]
    assert not verify_taproot_script_path(output_key, SCRIPT, forged)


@pytest.mark.parametrize("version", [0xC0, 0xC2, 0xFE, 0x66, 0x7E, 0x80, 0x84, 0x96, 0x98, 0xBA, 0xBC, 0xBE])
def test_permitted_leaf_versions_still_work(version: int) -> None:
    output_key, control = _commitment(2, version)
    assert verify_taproot_script_path(output_key, SCRIPT, control)


@pytest.mark.parametrize(
    "internal_key_x",
    [
        bytes(32),  # x = 0: 7 is not a square mod p, so no point has x = 0
        P.to_bytes(32, "big"),  # x must be below the field prime
        bytes([0xFF]) * 32,
    ],
)
def test_control_block_rejects_internal_keys_that_are_not_curve_points(
    internal_key_x: bytes,
) -> None:
    with pytest.raises(ValueError, match="internal key is not a valid x-only public key"):
        taproot_control_block(internal_key_x, 0)


@pytest.mark.parametrize(
    "output_key_x,script,control_block",
    [
        (INTERNAL, SCRIPT, "x" * 33),
        (None, SCRIPT, bytes([0xC0]) + INTERNAL),
        (INTERNAL, SCRIPT, None),
        (INTERNAL, None, bytes([0xC0]) + INTERNAL),
    ],
)
def test_script_path_verification_returns_false_for_malformed_input(
    output_key_x, script, control_block
) -> None:
    assert verify_taproot_script_path(output_key_x, script, control_block) is False
