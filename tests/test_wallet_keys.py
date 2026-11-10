"""Tests for OS-keyring WIF storage and the external signer contract."""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from keylab.encoding.wif import encode as encode_wif
from keylab.wallet.keys import HardwareSigner, KeyringProvider


class _MemoryCredentialBackend:
    __module__ = "keyring.backends.Windows.test_backend"

    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}


class _KeyringAPI(types.ModuleType):
    def __init__(self, backend: Any) -> None:
        super().__init__("keyring")
        self.backend = backend

    def get_keyring(self) -> Any:
        return self.backend

    def set_password(self, service: str, username: str, password: str) -> None:
        self.backend.values[(service, username)] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self.backend.values.get((service, username))

    def delete_password(self, service: str, username: str) -> None:
        del self.backend.values[(service, username)]


def test_keyring_provider_stores_and_retrieves_validated_testnet_wif(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _KeyringAPI(_MemoryCredentialBackend())
    monkeypatch.setitem(sys.modules, "keyring", api)
    provider = KeyringProvider()
    wif = encode_wif(1, network="testnet")

    provider.store_wif("throwaway-test-key", wif)

    assert provider.get_wif("throwaway-test-key") == wif
    provider.delete_wif("throwaway-test-key")
    with pytest.raises(KeyError, match="no WIF"):
        provider.get_wif("throwaway-test-key")


@pytest.mark.parametrize("alias", ["", " space", "../secret", "x" * 65])
def test_keyring_provider_rejects_unsafe_aliases(
    monkeypatch: pytest.MonkeyPatch,
    alias: str,
) -> None:
    monkeypatch.setitem(sys.modules, "keyring", _KeyringAPI(_MemoryCredentialBackend()))
    provider = KeyringProvider()
    with pytest.raises(ValueError, match="alias"):
        provider.store_wif(alias, encode_wif(1, network="testnet"))


def test_keyring_provider_rejects_non_os_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    class PlaintextBackend(_MemoryCredentialBackend):
        __module__ = "keyring.backends.fail"

    monkeypatch.setitem(sys.modules, "keyring", _KeyringAPI(PlaintextBackend()))
    with pytest.raises(RuntimeError, match="non-OS keyring backend"):
        KeyringProvider()


def test_keyring_provider_rejects_invalid_or_wrong_network_wif(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "keyring", _KeyringAPI(_MemoryCredentialBackend()))
    provider = KeyringProvider()
    with pytest.raises(ValueError, match="invalid WIF"):
        provider.store_wif("key", "not-a-wif")
    with pytest.raises(ValueError, match="only testnet/regtest"):
        provider.store_wif("key", encode_wif(1, network="mainnet"))


def test_hardware_signer_is_an_abstract_psbt_interface() -> None:
    with pytest.raises(TypeError):
        HardwareSigner()
