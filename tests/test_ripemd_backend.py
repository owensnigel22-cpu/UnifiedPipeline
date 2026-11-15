import os

import pytest

from keylab.encoding.address import hash160 as openssl_hash160
from keylab.hashes.ripemd_backend import (
    Ripemd160Backend,
    batch_hash160,
    default_backend,
    hash160,
)

# Published RIPEMD-160 test vectors (Dobbertin-Bosselaers-Preneel reference set).
_RIPEMD160_VECTORS = [
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
]

# Bitcoin genesis coinbase public key -> HASH160 (address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa).
_GENESIS_PUBKEY = bytes.fromhex(
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
    "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
)
_GENESIS_HASH160 = "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"


@pytest.mark.parametrize("message,expected", _RIPEMD160_VECTORS)
def test_backend_matches_published_ripemd160_vectors(message: bytes, expected: str) -> None:
    assert Ripemd160Backend().ripemd160(message).hex() == expected


def test_backend_hash160_matches_bitcoin_core_genesis_vector() -> None:
    assert Ripemd160Backend().hash160(_GENESIS_PUBKEY).hex() == _GENESIS_HASH160
    assert hash160(_GENESIS_PUBKEY).hex() == _GENESIS_HASH160


def test_backend_hash160_agrees_with_openssl_backend() -> None:
    pubkeys = [os.urandom(33) for _ in range(32)]
    backend = Ripemd160Backend()
    assert [backend.hash160(pk) for pk in pubkeys] == [openssl_hash160(pk) for pk in pubkeys]


def test_default_backend_is_pure_python_without_a_native_library() -> None:
    backend = default_backend()
    # No native library is bundled or on the path in the test environment.
    assert backend.is_native is False
    assert backend.name == "python"


def test_prefer_native_false_forces_pure_python() -> None:
    backend = Ripemd160Backend(prefer_native=False)
    assert backend.is_native is False
    assert backend.name == "python"


def test_missing_native_library_path_falls_back_without_error(tmp_path) -> None:
    # A nonexistent (or non-library) path must never crash the backend.
    backend = Ripemd160Backend(library_path=tmp_path / "does-not-exist.so")
    assert backend.is_native is False
    assert backend.ripemd160(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"


def test_batch_hash160_sequential_matches_per_key_hash160() -> None:
    pubkeys = [os.urandom(33) for _ in range(50)]
    backend = Ripemd160Backend()
    expected = [backend.hash160(pk) for pk in pubkeys]
    assert batch_hash160(pubkeys, use_processes=False) == expected


def test_batch_hash160_empty_input_returns_empty_list() -> None:
    assert batch_hash160([]) == []


@pytest.mark.slow
def test_batch_hash160_process_pool_preserves_order_and_values() -> None:
    pubkeys = [bytes([index]) + os.urandom(32) for index in range(8)]
    backend = Ripemd160Backend()
    expected = [backend.hash160(pk) for pk in pubkeys]
    # Force the process-pool path on a tiny input by lowering the threshold.
    result = batch_hash160(
        pubkeys, use_processes=True, max_workers=2, process_threshold=1
    )
    assert result == expected
