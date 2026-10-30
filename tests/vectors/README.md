# Official test vectors

These fixtures are copied or mechanically extracted from the Bitcoin BIPs
repository (<https://github.com/bitcoin/bips>, `master` branch, fetched
2026-10-30). Tests load them as data; nothing here is executed.

| File | Source | How produced |
|---|---|---|
| `bip340_test_vectors.csv` | `bip-0340/test-vectors.csv` | Verbatim copy (vectors 0–18, including variable-length messages 15–18) |

If a BIP is revised, refresh the verbatim files from the same paths and
re-extract the mediawiki vectors; do not edit expected values by hand.
