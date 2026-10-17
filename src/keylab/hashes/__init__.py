"""Reference hash implementations for research; not a general preimage-attack toolkit."""

from keylab.hashes.reduced import sha256_forward_feed, sha256_reverse_compress

__all__ = ["sha256_forward_feed", "sha256_reverse_compress"]
