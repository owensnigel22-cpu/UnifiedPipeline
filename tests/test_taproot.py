from keylab.ec.secp256k1 import P, public_key_from_private_scalar
from keylab.encoding.address import address_to_target_hash, p2tr_address
from keylab.encoding.taproot import (
    tapleaf_hash,
    taproot_control_block,
    taproot_output,
    taproot_output_from_point,
    verify_taproot_script_path,
)


def test_taproot_script_path_control_block_round_trip() -> None:
    internal_x = public_key_from_private_scalar(3)[0].to_bytes(32, "big")
    script = b"\x51"  # OP_TRUE; commitment test only, not script execution.
    root = tapleaf_hash(script)
    output = taproot_output(internal_x, root)
    control = taproot_control_block(internal_x, output.output_key_parity)

    assert output.address.startswith("bc1p")
    assert verify_taproot_script_path(output.output_key_x, script, control)
    assert not verify_taproot_script_path(output.output_key_x, b"\x00", control)


def test_taproot_key_only_output_uses_empty_merkle_root() -> None:
    internal_x = bytes.fromhex("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d")
    output = taproot_output(internal_x)
    assert output.merkle_root == b""
    assert output.tweak.to_bytes(32, "big").hex() == "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70"
    assert output.output_key_x.hex() == "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
    assert output.address == "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5"
    assert p2tr_address(internal_x) == output.address
    assert address_to_target_hash(output.address) == output.output_key_x


def test_taproot_known_point_path_matches_x_only_and_normalizes_y() -> None:
    point = public_key_from_private_scalar(3)
    x_only = point[0].to_bytes(32, "big")
    negative_point = (point[0], (-point[1]) % P)

    expected = taproot_output(x_only)
    assert taproot_output_from_point(point) == expected
    assert taproot_output_from_point(negative_point) == expected


def test_taproot_matches_bip341_script_path_vector() -> None:
    internal_x = bytes.fromhex("187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27")
    script = bytes.fromhex("20d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8ac")
    root = tapleaf_hash(script)
    assert root.hex() == "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21"
    output = taproot_output(internal_x, root)
    assert output.output_key_x.hex() == "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3"
    assert output.address == "bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586"
    control = bytes.fromhex("c1") + internal_x
    assert verify_taproot_script_path(output.output_key_x, script, control)
