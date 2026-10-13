"""WIF round-trip and public-vector tests; no real wallet secrets are used."""

import pytest

from keylab.encoding.wif import decode, encode


def test_known_mainnet_compressed_wif_vector() -> None:
    key, compressed, network = decode("KwHV8WDsBUuXPymuan5TQN82tPyRWZ68vb14ww8p9FFCw6a17xkR")
    assert encode(key, compressed, network) == "KwHV8WDsBUuXPymuan5TQN82tPyRWZ68vb14ww8p9FFCw6a17xkR"


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