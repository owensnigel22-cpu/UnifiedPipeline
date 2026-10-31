# Official test vectors

These fixtures are copied or mechanically extracted from the Bitcoin BIPs
repository (<https://github.com/bitcoin/bips>) and, for BIP-39, from the reference
implementation's vector file (<https://github.com/trezor/python-mnemonic>), fetched
2026-10-30. Tests load them as data; nothing here is executed.

Each source is pinned to the upstream commit it was taken from, with checksums,
in [`SOURCES.json`](SOURCES.json). `tests/test_vector_provenance.py` fails if a
fixture changes or a new one is added without an entry; `python scripts/vectors.py
fetch` re-downloads every source at its pinned commit and checks it.

| File | Source | How produced |
|---|---|---|
| `bip340_test_vectors.csv` | `bip-0340/test-vectors.csv` @ `200f9b26fe0a` | Verbatim copy (vectors 0–18, including variable-length messages 15–18) |
| `bip327_key_agg_vectors.json` | `bip-0327/vectors/key_agg_vectors.json` @ `87394eaeb436` | Verbatim copy |
| `bip327_key_sort_vectors.json` | `bip-0327/vectors/key_sort_vectors.json` @ `87394eaeb436` | Verbatim copy |
| `bip341_wallet_test_vectors.json` | `bip-0341/wallet-test-vectors.json` @ `e35a46ecf303` | Verbatim copy |
| `bip32_test_vectors.json` | `bip-0032.mediawiki` @ `c0644a054fd1` § Test Vectors 1–5 | Extracted by script from the mediawiki text |
| `bip39_trezor_vectors.json` | `trezor/python-mnemonic` `vectors.json` @ `b57a5ad77a98` (the BIP-39 reference vectors) | English subset copied verbatim (24 vectors, passphrase `TREZOR`) |
| `bech32_vectors.json` | `bip-0173.mediawiki` and `bip-0350.mediawiki` @ `24e96e870fff` § Test vectors | Extracted by script from the mediawiki text |
| `bip_derivation_vectors.json` | `bip-0049`, `bip-0084`, `bip-0086` mediawiki @ `24e96e870fff` § Test vectors | Extracted by script from the mediawiki text |

If a BIP is revised, refresh the verbatim files from the same paths and
re-extract the mediawiki vectors, then update the commit and checksums in
`SOURCES.json` in the same change; do not edit expected values by hand.
