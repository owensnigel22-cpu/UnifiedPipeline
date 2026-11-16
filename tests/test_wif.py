"""WIF round-trip and public-vector tests; no real wallet secrets are used."""

import pytest

from keylab.ec.secp256k1 import N
from keylab.encoding.wif import decode, encode


def test_known_mainnet_compressed_wif_vector() -> None:
    key, compressed, network = decode("KwHV8WDsBUuXPymuan5TQN82tPyRWZ68vb14ww8p9FFCw6a17xkR")
    assert (
        encode(key, compressed, network) == "KwHV8WDsBUuXPymuan5TQN82tPyRWZ68vb14ww8p9FFCw6a17xkR"
    )


@pytest.mark.parametrize("network", ["mainnet", "testnet"])
@pytest.mark.parametrize("compressed", [True, False])
def test_wif_round_trip(network: str, compressed: bool) -> None:
    key = (123456789).to_bytes(32, "big")
    assert decode(encode(key, compressed, network)) == (key, compressed, network)


def test_checksum_and_malformed_input_errors() -> None:
    with pytest.raises(ValueError, match="checksum"):
        decode("KwHV8WDsBUuXPymuan5TQN82tPyRWZ68vb14ww8p9FFCw6a17xkQ")
    with pytest.raises(ValueError, match="invalid WIF"):
        decode("not-a-wif")


def test_invalid_private_scalar_is_rejected() -> None:
    with pytest.raises(ValueError, match="private key"):
        encode(bytes(32))


@pytest.mark.parametrize("private_key", [True, False])
def test_boolean_private_key_is_rejected(private_key: bool) -> None:
    with pytest.raises(TypeError, match="boolean"):
        encode(private_key)


@pytest.mark.parametrize("private_key", [0, -1, N, N + 1])
def test_out_of_range_integer_private_key_is_rejected(private_key: int) -> None:
    with pytest.raises(ValueError, match="private key integer"):
        encode(private_key)


@pytest.mark.parametrize("private_key", [1, N - 1])
@pytest.mark.parametrize("network", ["mainnet", "testnet"])
@pytest.mark.parametrize("compressed", [True, False])
def test_integer_boundary_scalars_round_trip(
    private_key: int,
    network: str,
    compressed: bool,
) -> None:
    key_bytes = private_key.to_bytes(32, "big")
    assert decode(encode(private_key, compressed, network)) == (
        key_bytes,
        compressed,
        network,
    )
