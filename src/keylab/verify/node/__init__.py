"""Bitcoin Core node connectivity used by wallet state queries.

The node client is separate from the read-only public explorer used by M7.
Bitcoin Core RPC credentials are powerful; see ``SECURITY.md`` before enabling
remote access.
"""

from keylab.verify.node.client import BitcoinRPCClient, BitcoinRPCError

__all__ = ["BitcoinRPCClient", "BitcoinRPCError"]
