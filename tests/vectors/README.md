# Official test vectors

These fixtures are copied or mechanically extracted from the Bitcoin BIPs
repository (<https://github.com/bitcoin/bips>, `master` branch, fetched
2026-10-30). Tests load them as data; nothing here is executed.

| File | Source | How produced |
|---|---|---|
| `bip340_test_vectors.csv` | `bip-0340/test-vectors.csv` | Verbatim copy (vectors 0–18, including variable-length messages 15–18) |
| `bip327_key_agg_vectors.json` | `bip-0327/vectors/key_agg_vectors.json` | Verbatim copy |
| `bip327_key_sort_vectors.json` | `bip-0327/vectors/key_sort_vectors.json` | Verbatim copy |

If a BIP is revised, refresh the verbatim files from the same paths and
re-extract the mediawiki vectors; do not edit expected values by hand.
