"""Educational ECDSA failure-mode demonstrations (nonce reuse, nonce bias / HNP,
bounded nonce pre-image).

Governed by docs/SECURITY_POSITIONING.md: these recover a private scalar or nonce
only from signatures that already leak the information the mathematics requires (a
reused nonce, a stated nonce bias, or a nonce confined to a declared interval).
Given correct ECDSA with unique uniform nonces they recover nothing. Every
returned scalar is forward-verified. Teaching aids, never on the signing path;
they accept no real wallet/WIF/seed inputs. See SECURITY.md.
"""

from __future__ import annotations

from keylab.research.ecdsa.nonce_preimage import recover_nonce_in_range
from keylab.research.ecdsa.nonce_reuse import recover_private_key_from_nonce_reuse

__all__ = ["recover_nonce_in_range", "recover_private_key_from_nonce_reuse"]
