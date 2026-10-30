# Official test vectors

These fixtures are copied or mechanically extracted from the Bitcoin BIPs
repository (<https://github.com/bitcoin/bips>, `master` branch, fetched
2026-10-30) and, for BIP-39, from the reference implementation's vector file
(<https://github.com/trezor/python-mnemonic>, fetched 2026-10-30). Tests load them as data; nothing here is executed.

| File | Source | How produced |
|---|---|---|
| `bip340_test_vectors.csv` | `bip-0340/test-vectors.csv` | Verbatim copy (vectors 0–18, including variable-length messages 15–18) |
| `bip327_key_agg_vectors.json` | `bip-0327/vectors/key_agg_vectors.json` | Verbatim copy |
| `bip327_key_sort_vectors.json` | `bip-0327/vectors/key_sort_vectors.json` | Verbatim copy |
| `bip341_wallet_test_vectors.json` | `bip-0341/wallet-test-vectors.json` | Verbatim copy |
| `bip32_test_vectors.json` | `bip-0032.mediawiki` § Test Vectors 1–5 | Extracted by script from the mediawiki text |
| `bip39_trezor_vectors.json` | `trezor/python-mnemonic` `vectors.json` (the BIP-39 reference vectors) | English subset copied verbatim (24 vectors, passphrase `TREZOR`) |
| `bip_derivation_vectors.json` | `bip-0049`, `bip-0084`, `bip-0086` mediawiki § Test vectors | Extracted by script from the mediawiki text |

If a BIP is revised, refresh the verbatim files from the same paths and
re-extract the mediawiki vectors; do not edit expected values by hand.
