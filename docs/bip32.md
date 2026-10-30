# BIP-32 hierarchical deterministic keys

Module: `keylab.hd`.

## Model

`ExtendedKey(key, chain_code, is_private, depth, parent_fingerprint, child_number, family)`

- `key` is a 32-byte private key or a 33-byte compressed public key.
- `family` picks the serialization version bytes:

| Family | Private / public | Use |
|---|---|---|
| `x` | `xprv` / `xpub` | BIP-32, BIP-44, BIP-86 mainnet |
| `t` | `tprv` / `tpub` | testnet |
| `y` / `u` | `yprv`/`ypub`, `uprv`/`upub` | BIP-49 mainnet / testnet (SLIP-132) |
| `z` / `v` | `zprv`/`zpub`, `vprv`/`vpub` | BIP-84 mainnet / testnet (SLIP-132) |

```python
from keylab.hd import ExtendedKey, derive_account_key, mnemonic_to_seed

seed = mnemonic_to_seed("abandon " * 11 + "about")
root = ExtendedKey.from_seed(seed)
account = root.derive("m/84'/0'/0'").with_family("z")   # same as derive_account_key(seed, 84)
xpub = account.neuter()
child = xpub.child(0).child(5)                           # CKDpub, no secrets needed
print(account.fingerprint.hex(), child.parent_fingerprint.hex())
```

## Operations

| Operation | API |
|---|---|
| Master key from seed | `ExtendedKey.from_seed`, `master_key` |
| CKDpriv | `ExtendedKey.child`, `derive_child_private` |
| CKDpub (non-hardened only) | `ExtendedKey.child` on a public key, `derive_child_public` |
| Neuter (xprv → xpub) | `ExtendedKey.neuter` |
| Identifier / fingerprint | `ExtendedKey.identifier`, `.fingerprint`, `key_identifier`, `fingerprint` |
| Parse / serialize | `ExtendedKey.parse`, `.serialize` |
| Paths | `parse_path`, `format_path` (`'`, `h`, `H` accepted as hardened markers) |
| BIP-44/49/84/86 addresses | `derive_bip44_p2pkh`, `derive_bip49_p2sh_p2wpkh`, `derive_bip84_p2wpkh`, `derive_bip86_p2tr` (all take `change=0/1`) |
| Account keys | `derive_account_key(seed, purpose, account, network=)` |
| Batch BIP-44 | `derive_bip44_accounts` (reuses account/external nodes) |
| Non-hardened compromise demo | `recover_unhardened_parent_private_key` |

## Parsing is strict

`ExtendedKey.parse` rejects every defect listed in BIP-32 test vector 5:
version/key-type mismatch, `0x04`/`0x01` key prefixes, depth-0 keys with a
parent fingerprint or index, unknown versions, private keys equal to 0 or N,
public keys not on the curve, and checksum errors.

## Test coverage

`tests/test_bip32_vectors.py` runs the official vectors from
`tests/vectors/` (see its README for provenance):

- BIP-32 vectors 1-4: all 17 chains, xprv and xpub, serialization round trips,
  and CKDpub agreement at every non-hardened step.
- BIP-32 vector 5: all 16 invalid keys.
- BIP-49 (testnet `uprv`/`upub`, P2SH-P2WPKH), BIP-84 (`zprv`/`zpub`,
  P2WPKH receive and change), BIP-86 (root, account, receive, change, output
  keys, and addresses).

## Limitations

- BIP-39 word lists and mnemonic checksum validation are not included;
  `mnemonic_to_seed` assumes a valid phrase.
- Invalid-child cases (probability ≈ 2⁻¹²⁷) raise instead of silently skipping
  the index; the caller must advance to the next index, as BIP-32 specifies.
- Private derivation is not constant-time (see `SECURITY.md`).
