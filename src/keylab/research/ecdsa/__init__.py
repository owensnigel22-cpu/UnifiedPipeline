"""Educational ECDSA failure-mode demonstrations (nonce reuse, nonce bias / HNP).

Governed by docs/SECURITY_POSITIONING.md: these recover a private scalar only
from signatures that already leak the information the mathematics requires (a
reused nonce, or nonces with a stated, known bias). Given correct ECDSA with
unique uniform nonces they recover nothing. Every returned scalar is forward-
verified (d*G == public key). Teaching aids, never on the signing path; they
accept no real wallet/WIF/seed inputs. See SECURITY.md.
"""

from __future__ import annotations

from keylab.research.ecdsa.nonce_reuse import recover_private_key_from_nonce_reuse

__all__ = ["recover_private_key_from_nonce_reuse"]
