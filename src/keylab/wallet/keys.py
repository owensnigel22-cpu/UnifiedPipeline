"""OS-keyring storage and signer interfaces for test-network wallet research.

This module stores WIF strings using an OS credential manager. It does not
provide a plaintext-file fallback, and it cannot make Python secret handling
constant-time or guarantee memory erasure. Use synthetic testnet/regtest keys
only; never use this module for keys controlling real funds.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any

from keylab.encoding.wif import decode as decode_wif

_OS_BACKEND_PREFIXES = (
    "keyring.backends.Windows.",
    "keyring.backends.macOS.",
    "keyring.backends.SecretService.",
    "keyring.backends.kwallet.",
)
_ALIAS_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class KeyringProvider:
    """Store and retrieve validated WIFs through a recognized OS keyring.

    The provider refuses unknown, fail, and alternate backends. The strict
    backend allowlist may need an explicit review before supporting a new
    operating-system credential manager.
    """

    def __init__(self, service_name: str = "keylab.wallet") -> None:
        if not isinstance(service_name, str) or not service_name.strip():
            raise ValueError("service_name must be a non-empty string")
        try:
            import keyring
        except ImportError as exc:
            raise RuntimeError("KeyringProvider requires the optional 'wallet' extra") from exc

        backend = keyring.get_keyring()
        backend_module = type(backend).__module__
        if not backend_module.startswith(_OS_BACKEND_PREFIXES):
            raise RuntimeError(
                "refusing non-OS keyring backend; configure a supported native credential manager"
            )
        self._keyring: Any = keyring
        self._service_name = service_name

    @staticmethod
    def _validate_alias(alias: str) -> None:
        if not isinstance(alias, str) or _ALIAS_RE.fullmatch(alias) is None:
            raise ValueError("alias must be 1-64 safe ASCII letters, digits, dots, underscores, or hyphens")

    @staticmethod
    def _validate_wif(wif: str) -> str:
        if not isinstance(wif, str):
            raise TypeError("WIF must be a string")
        _, _, network = decode_wif(wif)
        if network != "testnet":
            raise ValueError("KeyringProvider accepts only testnet/regtest WIFs in M12")
        return wif

    def store_wif(self, alias: str, wif: str) -> None:
        """Validate and store a WIF without writing it to a project file."""
        self._validate_alias(alias)
        secret = self._validate_wif(wif)
        self._keyring.set_password(self._service_name, alias, secret)

    def get_wif(self, alias: str) -> str:
        """Retrieve and revalidate a WIF; missing aliases raise ``KeyError``."""
        self._validate_alias(alias)
        secret = self._keyring.get_password(self._service_name, alias)
        if secret is None:
            raise KeyError(f"no WIF stored for alias {alias!r}")
        return self._validate_wif(secret)

    def delete_wif(self, alias: str) -> None:
        """Delete a stored WIF, raising ``KeyError`` when the alias is absent."""
        self._validate_alias(alias)
        if self._keyring.get_password(self._service_name, alias) is None:
            raise KeyError(f"no WIF stored for alias {alias!r}")
        self._keyring.delete_password(self._service_name, alias)


class HardwareSigner(ABC):
    """Vendor-neutral PSBT handoff interface for an external hardware signer.

    Implementations must send the PSBT to the device for on-device transaction
    review and confirmation, and return the signed PSBT. They must not expose
    private keys or silently approve a transaction. Device transport is not
    implemented in this milestone.
    """

    @abstractmethod
    def sign_psbt(self, psbt: bytes, *, network: str) -> bytes:
        """Return a device-signed PSBT after device-side user confirmation."""


__all__ = ["HardwareSigner", "KeyringProvider"]
