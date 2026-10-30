import hashlib

import pytest

from keylab.advanced_suite import (
    batch_inv,
    parse_pubkey,
    rfc6979_deterministic_nonce,
    rfc6979_trace,
)
from keylab.ec.secp256k1 import compress_pubkey, decompress_pubkey, rfc6979_nonce_from_digest


def test_batch_inv_handles_zero_and_normalizes_inputs_in_order() -> None:
    modulus = 101
    values = [2, 0, 5, -3, 101]
    inverses = batch_inv(values, modulus)

    assert inverses == [51, 0, 81, 67, 0]
    assert all((value * inverse) % modulus == 1 for value, inverse in zip(values, inverses) if value % modulus)
    assert batch_inv([], modulus) == []


@pytest.mark.parametrize("values,modulus", [([1, True], 101), ([1], 1)])
def test_batch_inv_rejects_bad_inputs(values: list[int], modulus: int) -> None:
    with pytest.raises(ValueError):
        batch_inv(values, modulus)


def test_advanced_suite_rfc6979_wrapper_matches_shared_digest_api() -> None:
    private_scalar = 7
    digest = hashlib.sha256(b"RFC6979 shared implementation").digest()
    nonce = rfc6979_nonce_from_digest(private_scalar, digest)

    assert rfc6979_deterministic_nonce(private_scalar, int.from_bytes(digest, "big")) == nonce


def test_rfc6979_trace_matches_shared_nonce_api() -> None:
    private_scalar = 7
    message = "Trace consistency check"
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    trace = rfc6979_trace(private_scalar, message)

    assert trace["rfc6979_k_hex"] == f"0x{rfc6979_nonce_from_digest(private_scalar, digest):064x}"


ODD_Y_KEY = "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"


def test_advanced_suite_parse_pubkey_honours_odd_y_prefix() -> None:
    # Regression: 0x03 keys used to parse to the even-y point.
    parsed = parse_pubkey(ODD_Y_KEY)
    assert parsed == decompress_pubkey(bytes.fromhex(ODD_Y_KEY))
    assert parsed[1] % 2 == 1
    assert compress_pubkey(parsed).hex().upper() == ODD_Y_KEY
    assert parse_pubkey(ODD_Y_KEY[2:])[1] % 2 == 0  # x-only lifts to even y
