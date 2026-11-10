"""Network identifiers and local Bitcoin Core endpoint defaults."""

from __future__ import annotations

from enum import Enum


class Network(str, Enum):
    """Bitcoin Core chain selection supported by the M12 node client."""

    MAINNET = "mainnet"
    TESTNET = "testnet"
    REGTEST = "regtest"

    @property
    def rpc_chain(self) -> str:
        """Bitcoin Core's ``getblockchaininfo.chain`` identifier."""
        return {
            Network.MAINNET: "main",
            Network.TESTNET: "test",
            Network.REGTEST: "regtest",
        }[self]


DEFAULT_RPC_URLS: dict[Network, str] = {
    Network.MAINNET: "http://127.0.0.1:8332/",
    Network.TESTNET: "http://127.0.0.1:18332/",
    Network.REGTEST: "http://127.0.0.1:18443/",
}


def default_rpc_url(network: Network) -> str:
    """Return the loopback URL for a Bitcoin Core chain's conventional RPC port."""
    if not isinstance(network, Network):
        raise TypeError("network must be a Network value")
    return DEFAULT_RPC_URLS[network]


__all__ = ["DEFAULT_RPC_URLS", "Network", "default_rpc_url"]
