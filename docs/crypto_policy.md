# Crypto policy, constant-time compare, and HKDF domain separation

Teaching/reference material. KeyLab is research/teaching code, not production
wallet software; see [SECURITY.md](../SECURITY.md). The pieces below are
primitives and conventions, not a certification of any implementation.

## Algorithm allow-list (`keylab.crypto_policy`)

A small, centralized statement of what KeyLab considers acceptable **for study**:

- **Hashes:** `sha256`, `sha384`, `sha512` (SHA-1/MD5 excluded).
- **Signature schemes:** `ecdsa-secp256k1`, `schnorr-bip340`, `rsa-pss-sha256`
  (RSA PKCS#1 v1.5 excluded for new signatures).
- **RSA key size:** minimum 2048 bits.

The module is **advisory** — a library primitive with **zero production callers**.
It does not change any existing behaviour: `require_hash`, `require_signature_scheme`,
and `require_rsa_key_bits` raise `PolicyError` for out-of-list inputs, and
`is_allowed_*` return booleans, for new code or tests that choose to validate
through it.

Deliberate non-enforcement: `keylab.crypto.generate_rsa_keypair` is **not** gated
by `require_rsa_key_bits`, because teaching examples legitimately use small RSA
keys (e.g. 512-bit) to keep the arithmetic tractable. A strict, opt-in path could
be added by a future milestone if wanted. There is no AEAD/symmetric category yet;
one will be added when a consumer exists.

## Constant-time comparison (`keylab._ct.constant_time_equal`)

A single leaf helper wrapping the standard library's `hmac.compare_digest`. Use
it instead of `==` when comparing MACs, tags, or other secret-dependent bytes.
A length mismatch returns `False` (no exception, no early-out on the first byte);
non-bytes inputs raise `TypeError`. Timing invariance is provided by the stdlib
primitive. KeyLab's HMAC verification and RSA OAEP/PSS checks route through it.

## HKDF domain separation (`keylab.crypto.hkdf`)

HKDF (RFC 5869) derives independent keys from one input keying material (IKM) by
**context label** (`info`):

- Distinct `info` values → independent keys from the same IKM. When deriving
  several keys from one master secret, give each a distinct `info` (e.g. `b"enc"`
  vs `b"mac"`). Reusing a label for two purposes lets one key substitute for
  another.
- Same IKM + same `info` + same `salt` + same `hash_name` → identical output
  (deterministic).
- Changing `salt` or `hash_name` also changes the output.

Example:

```python
from keylab.crypto import hkdf
master = b"...32+ bytes of high-entropy IKM..."
enc_key = hkdf(master, 32, salt=b"app-salt", info=b"enc")
mac_key = hkdf(master, 32, salt=b"app-salt", info=b"mac")
assert enc_key != mac_key  # distinct domains -> distinct keys
```
