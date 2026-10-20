"""BIP-341 Taproot output-key and script-path commitment utilities.

These helpers construct and verify commitment data; they do not execute Bitcoin
Script or validate spending conditions such as signatures and timelocks.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from keylab.ec.secp256k1 import G, N, P, is_on_curve, point_add_affine, scalar_mult
from keylab.encoding.bech32 import encode_segwit_address


def tagged_hash(tag: str, message: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def lift_x(x: int) -> tuple[int, int]:
    """Lift a valid x-only secp256k1 public key to the even-y point."""
    if type(x) is not int or not 0 <= x < P:
        raise ValueError("x coordinate must be in the secp256k1 field")
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        raise ValueError("x coordinate does not lift to secp256k1")
    return x, y if y % 2 == 0 else P - y


def tapleaf_hash(script: bytes, leaf_version: int = 0xC0) -> bytes:
    """Compute the BIP-341 TapLeaf hash using Bitcoin's CompactSize length."""
    if not isinstance(script, bytes):
        raise TypeError("script must be bytes")
    if type(leaf_version) is not int or not 0 <= leaf_version <= 0xFE or leaf_version & 1:
        raise ValueError("leaf version must be an even byte")
    length = len(script)
    if length < 253:
        compact_size = bytes([length])
    elif length <= 0xFFFF:
        compact_size = b"\xfd" + length.to_bytes(2, "little")
    elif length <= 0xFFFFFFFF:
        compact_size = b"\xfe" + length.to_bytes(4, "little")
    else:
        compact_size = b"\xff" + length.to_bytes(8, "little")
    return tagged_hash("TapLeaf", bytes([leaf_version]) + compact_size + script)


def tapbranch_hash(left: bytes, right: bytes) -> bytes:
    """Combine two 32-byte Taproot nodes in lexicographic order."""
    if len(left) != 32 or len(right) != 32:
        raise ValueError("TapBranch children must each be 32 bytes")
    first, second = sorted((left, right))
    return tagged_hash("TapBranch", first + second)


@dataclass(frozen=True)
class TaprootOutput:
    internal_key_x: bytes
    merkle_root: bytes
    tweak: int
    output_key_x: bytes
    output_key_parity: int
    address: str


def _taproot_output(
    internal_key_x: bytes,
    internal: tuple[int, int],
    merkle_root: bytes,
    network: str,
) -> TaprootOutput:
    if len(internal_key_x) != 32:
        raise ValueError("internal x-only key must be 32 bytes")
    if merkle_root and len(merkle_root) != 32:
        raise ValueError("Merkle root must be empty or 32 bytes")
    hrp = {"mainnet": "bc", "testnet": "tb", "regtest": "bcrt"}.get(network)
    if hrp is None:
        raise ValueError("network must be mainnet, testnet, or regtest")
    tweak_bytes = tagged_hash("TapTweak", internal_key_x + merkle_root)
    tweak = int.from_bytes(tweak_bytes, "big")
    if tweak >= N:
        raise ValueError("TapTweak hash is outside the curve order")
    output = point_add_affine(internal, scalar_mult(tweak, G))
    if output is None:
        raise ValueError("Taproot tweak produced the point at infinity")
    output_x, output_y = output
    x_bytes = output_x.to_bytes(32, "big")
    return TaprootOutput(internal_key_x, merkle_root, tweak, x_bytes, output_y & 1,
                         encode_segwit_address(hrp, 1, x_bytes))


def taproot_output(internal_key_x: bytes, merkle_root: bytes = b"", *, network: str = "mainnet") -> TaprootOutput:
    """Compute BIP-341 Q=P+tG from an x-only internal key.

    ``merkle_root`` must be empty for key-path-only outputs or 32 bytes for a
    script tree. Internal keys are lifted to their even-y point. Callers that
    already have the full point can avoid the square-root lift with
    :func:`taproot_output_from_point`.
    """
    if not isinstance(internal_key_x, bytes) or len(internal_key_x) != 32:
        raise ValueError("internal x-only key must be 32 bytes")
    internal = lift_x(int.from_bytes(internal_key_x, "big"))
    return _taproot_output(internal_key_x, internal, merkle_root, network)


def taproot_output_from_point(
    internal_point: tuple[int, int],
    merkle_root: bytes = b"",
    *,
    network: str = "mainnet",
) -> TaprootOutput:
    """Compute Taproot output data from a known point, avoiding a redundant lift_x.

    The x-only internal key uses the even-y representative mandated by BIP-341.
    """
    if not isinstance(internal_point, tuple) or len(internal_point) != 2 or not is_on_curve(internal_point):
        raise ValueError("internal_point must be a valid secp256k1 affine point")
    x, y = internal_point
    normalized = (x, y if y % 2 == 0 else P - y)
    return _taproot_output(x.to_bytes(32, "big"), normalized, merkle_root, network)


def taproot_control_block(internal_key_x: bytes, output_key_parity: int,
                          merkle_path: Sequence[bytes] = (), *, leaf_version: int = 0xC0) -> bytes:
    """Serialize BIP-341 control block for one leaf and its Merkle path."""
    if len(internal_key_x) != 32:
        raise ValueError("internal x-only key must be 32 bytes")
    if output_key_parity not in (0, 1):
        raise ValueError("output parity must be 0 or 1")
    if len(merkle_path) > 128 or any(len(node) != 32 for node in merkle_path):
        raise ValueError("Merkle path must contain at most 128 32-byte nodes")
    if leaf_version & 1 or not 0 <= leaf_version <= 0xFE:
        raise ValueError("leaf version must be an even byte")
    return bytes([leaf_version | output_key_parity]) + internal_key_x + b"".join(merkle_path)


def verify_taproot_script_path(output_key_x: bytes, script: bytes, control_block: bytes) -> bool:
    """Verify control-block commitment to an output key (not script execution)."""
    if len(output_key_x) != 32 or len(control_block) < 33 or (len(control_block) - 33) % 32:
        return False
    leaf_version = control_block[0] & 0xFE
    parity = control_block[0] & 1
    internal_x = control_block[1:33]
    path = [control_block[i:i + 32] for i in range(33, len(control_block), 32)]
    try:
        root = tapleaf_hash(script, leaf_version)
        for node in path:
            root = tapbranch_hash(root, node)
        output = taproot_output(internal_x, root)
    except (ValueError, TypeError):
        return False
    return output.output_key_x == output_key_x and output.output_key_parity == parity


__all__ = ["TaprootOutput", "lift_x", "tagged_hash", "tapbranch_hash", "tapleaf_hash",
           "taproot_control_block", "taproot_output", "taproot_output_from_point", "verify_taproot_script_path"]
