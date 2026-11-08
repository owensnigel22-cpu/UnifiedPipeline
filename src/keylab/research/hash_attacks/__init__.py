"""Educational SHA-256 attack demonstrations at reduced/truncated scale.

Two well-known facts shown at a scale that fits the honest wall:
truncated-digest pre-image by brute force (cost 2**bits, bits <= 40), and
Merkle-Damgard length extension (reusing keylab.hashes.length_extension). The
full SHA-256 pre-image is 2**256 (~10^60 years) and is never attempted. Neither
threatens SHA-256's pre-image or collision resistance. See SECURITY.md.
"""

from __future__ import annotations

from keylab.research.hash_attacks.length_extension_demo import (
    LengthExtensionReport,
    demonstrate_length_extension,
)
from keylab.research.hash_attacks.truncated_preimage import (
    MAX_BITS,
    PreimageResult,
    find_truncated_preimage,
    truncated_prefix,
)

__all__ = [
    "MAX_BITS",
    "LengthExtensionReport",
    "PreimageResult",
    "demonstrate_length_extension",
    "find_truncated_preimage",
    "truncated_prefix",
]
