from keylab.ec.schnorr import schnorr_public_key, schnorr_sign, schnorr_verify
from keylab.ec.sec1 import parse_sec1, serialize_sec1
from keylab.ec.secp256k1 import G, N, compress_pubkey, point_add_affine


def test_bip340_official_signing_vector_zero() -> None:
    secret = 3
    message = bytes(32)
    aux = bytes(32)
    public_key = bytes.fromhex("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
    signature = bytes.fromhex(
        "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215"
        "25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
    )
    assert schnorr_public_key(secret) == public_key
    assert schnorr_sign(message, secret, aux) == signature
    assert schnorr_verify(message, signature, public_key)
    assert not schnorr_verify(b"x" * 32, signature, public_key)
    changed_signature = bytes((signature[0] ^ 1,)) + signature[1:]
    assert not schnorr_verify(message, changed_signature, public_key)


def test_bip340_rejects_malformed_or_out_of_range_values() -> None:
    message = bytes(32)
    assert not schnorr_verify(message, bytes(63), bytes(32))
    assert not schnorr_verify(message, bytes(32) + N.to_bytes(32, "big"), bytes(32))
    assert not schnorr_verify(message, bytes(32) + bytes(32), (2**256 - 1).to_bytes(32, "big"))


def test_sec1_roundtrips_compressed_and_uncompressed_encodings() -> None:
    points = (G, point_add_affine(G, G), point_add_affine(point_add_affine(G, G), G))
    for point in points:
        compressed = serialize_sec1(point)
        uncompressed = serialize_sec1(point, compressed=False)
        assert compressed == compress_pubkey(point)
        assert parse_sec1(compressed) == point
        assert parse_sec1(uncompressed) == point
        assert serialize_sec1(parse_sec1(uncompressed), compressed=False) == uncompressed


def test_sec1_parser_rejects_invalid_points_and_encodings() -> None:
    for encoded in (b"", b"\x04" + bytes(64), b"\x02" + (2**256 - 1).to_bytes(32, "big")):
        try:
            parse_sec1(encoded)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid SEC1 key was accepted")
