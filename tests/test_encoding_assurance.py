import pytest

from keylab.ec.sec1 import serialize_sec1
from keylab.ec.secp256k1 import G, N
from keylab.encoding.address import p2pkh_address
from keylab.encoding.base58 import b58decode, b58encode, check_encode
from keylab.encoding.wif import decode as decode_wif


def test_base58_preserves_multiple_leading_zero_bytes() -> None:
    payload = b"\x00\x00\x01\x02\x00"

    assert b58decode(b58encode(payload)) == payload


@pytest.mark.parametrize(
    "payload",
    [
        b"\x81" + (1).to_bytes(32, "big"),
        b"\x80" + bytes(31),
        b"\x80" + (1).to_bytes(32, "big") + b"\x02",
        b"\x80" + bytes(32),
        b"\x80" + N.to_bytes(32, "big"),
    ],
)
def test_wif_decode_rejects_checksum_valid_malformed_payloads(payload: bytes) -> None:
    with pytest.raises(ValueError):
        decode_wif(check_encode(payload))


@pytest.mark.parametrize(
    "public_key",
    [
        b"",
        b"not SEC1",
        b"\x04" + bytes(64),
        b"\x02" + bytes(32),
    ],
)
def test_p2pkh_rejects_malformed_or_invalid_sec1_keys(public_key: bytes) -> None:
    with pytest.raises(ValueError):
        p2pkh_address(public_key)


def test_p2pkh_rejects_non_byte_public_keys() -> None:
    with pytest.raises(TypeError, match="public_key must be bytes"):
        p2pkh_address("not bytes")  # type: ignore[arg-type]


def test_p2pkh_preserves_compressed_and_uncompressed_address_vectors() -> None:
    assert p2pkh_address(serialize_sec1(G)) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    assert p2pkh_address(serialize_sec1(G, compressed=False)) == (
        "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
    )
