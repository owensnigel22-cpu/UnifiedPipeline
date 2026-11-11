"""Network-aware broadcast routing for a pre-signed transaction.

Routes a signed ``raw_tx_hex`` to a broadcaster for its network. **Mainnet
requires one explicit confirmation** (``confirm_mainnet=True``) -- an informed,
single opt-in, kept deliberately so an irreversible mainnet broadcast is never
fired silently. The broadcasters handle no keys.

Signing a mainnet transaction must use the audited coincurve/libsecp256k1 backend
(:func:`require_coincurve_for_mainnet`): the pure-Python ECC is non-constant-time
and unsuitable for real-value secret keys (see SECURITY.md).
"""

from __future__ import annotations

from keylab.verify.node import Network
from keylab.wallet.broadcast_api import Broadcaster, MempoolSpaceBroadcaster

__all__ = [
    "MainnetConfirmationError",
    "broadcast",
    "default_broadcaster",
    "require_coincurve_for_mainnet",
]


class MainnetConfirmationError(RuntimeError):
    """Raised when a mainnet broadcast is attempted without explicit confirmation."""


def default_broadcaster(network: Network) -> Broadcaster:
    """Return the default broadcaster for a network (mempool.space HTTP API)."""
    return MempoolSpaceBroadcaster(network)


def require_coincurve_for_mainnet(network: Network) -> None:
    """Ensure mainnet signing uses the audited coincurve backend; raise if unavailable.

    For ``Network.MAINNET`` this verifies libsecp256k1 (via Coincurve) is present so
    real-value keys are never signed by the non-constant-time pure-Python path. A
    no-op for test networks.
    """
    if network is Network.MAINNET:
        from keylab.ec.coincurve_backend import _coincurve
        _coincurve()  # raises ImportError with an install hint if the backend is missing


def broadcast(
    raw_tx_hex: str, network: Network, *,
    confirm_mainnet: bool = False, broadcaster: Broadcaster | None = None,
) -> str:
    """Broadcast a pre-signed transaction, returning the txid.

    ``network`` selects the default broadcaster unless one is injected. A
    ``Network.MAINNET`` broadcast requires ``confirm_mainnet=True`` (one explicit,
    informed confirmation) and raises :class:`MainnetConfirmationError` otherwise.
    """
    if not isinstance(network, Network):
        raise TypeError("network must be a Network value")
    if network is Network.MAINNET and confirm_mainnet is not True:
        raise MainnetConfirmationError(
            "mainnet broadcast requires an explicit confirmation (confirm_mainnet=True); "
            "this sends an irreversible transaction with real funds"
        )
    client = broadcaster if broadcaster is not None else default_broadcaster(network)
    return client.broadcast(raw_tx_hex)
