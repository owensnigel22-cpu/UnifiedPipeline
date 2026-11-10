"""Wallet workflow interfaces, including mainnet broadcasting (M14).

Pre-signed transactions can be broadcast to any network via HTTP explorer APIs
(:mod:`keylab.wallet.broadcast_api`) or directly over P2P
(:mod:`keylab.wallet.broadcast_p2p`); :func:`keylab.wallet.broadcast.broadcast`
routes by network and requires one explicit confirmation for mainnet.

Signing real-value (mainnet) keys must use the audited coincurve/libsecp256k1
backend (:func:`keylab.wallet.broadcast.require_coincurve_for_mainnet`): the
pure-Python ECC is **non-constant-time** and unsuitable for secret keys. See
``SECURITY.md``.
"""

from keylab.wallet.broadcast import (
    MainnetConfirmationError,
    broadcast,
    default_broadcaster,
    require_coincurve_for_mainnet,
)
from keylab.wallet.broadcast_api import (
    BlockCypherBroadcaster,
    Broadcaster,
    BroadcastError,
    MempoolSpaceBroadcaster,
)
from keylab.wallet.broadcast_p2p import P2PBroadcaster, P2PBroadcastError
from keylab.wallet.keys import HardwareSigner, KeyringProvider

__all__ = [
    "BlockCypherBroadcaster",
    "BroadcastError",
    "Broadcaster",
    "HardwareSigner",
    "KeyringProvider",
    "MainnetConfirmationError",
    "MempoolSpaceBroadcaster",
    "P2PBroadcastError",
    "P2PBroadcaster",
    "broadcast",
    "default_broadcaster",
    "require_coincurve_for_mainnet",
]
