# References — production implementations and primitives

KeyLab is a readable, educational Python implementation checked against official
test vectors. It is **not** production secret-key software (see
[../SECURITY.md](../SECURITY.md)). For real keys and funds, use a reviewed,
constant-time implementation. The repositories below are the production-grade
references KeyLab's behaviour is cross-checked against or models after; they are
cited for study and are not vendored into this project.

## secp256k1 (ECC, ECDSA, Schnorr)

| Project | Language | What it is / why it is referenced |
|---|---|---|
| [`bitcoin-core/secp256k1`](https://github.com/bitcoin-core/secp256k1) | C | The canonical, constant-time, side-channel-hardened secp256k1 library used by Bitcoin Core. The gold standard for ECDSA/Schnorr (BIP-340) and the differential-test oracle KeyLab aims to match. |
| [`paritytech/libsecp256k1`](https://github.com/paritytech/libsecp256k1) | Rust | A pure-Rust secp256k1 (ECDSA, recovery) used in the Polkadot/Substrate ecosystem; a readable, memory-safe reference for the same primitives. |
| [`paulmillr/noble-secp256k1`](https://github.com/paulmillr/noble-secp256k1) | JavaScript/TypeScript | A minimal, auditable, zero-dependency JS implementation (ECDSA, Schnorr, ECDH). Useful as a second independent reference for field/curve arithmetic and RFC 6979. |
| [`MetacoSA/NBitcoin.Secp256k1`](https://github.com/MetacoSA/NBitcoin) | C# | The managed secp256k1 used by NBitcoin; a reference for the same operations in the .NET ecosystem. |

## Hash primitives (SHA-256, RFC 6979)

| Project | Language | What it is / why it is referenced |
|---|---|---|
| [`bitpart-xyz/rfc6234`](https://github.com/bitpart-xyz/rfc6234) | C | SHA-224/256/384/512 and HMAC per RFC 6234 — the hashing underlying RFC 6979 deterministic nonces and Bitcoin's double-SHA256. |
| [`ma-ilsi/porridge`](https://github.com/ma-ilsi/porridge) | C99 | A compact C99 implementation of RFC 6979 deterministic ECDSA nonce generation — the C counterpart to `keylab.ec.rfc6979` (which delegates to the Python `ecdsa` library) and KeyLab's own `rfc6979_nonce_from_digest`. |

## How KeyLab uses these

- **Differential testing**: KeyLab's multiplication, point addition/doubling,
  SEC1 encoding, ECDSA and BIP-340 signatures are checked against
  `libsecp256k1` (via `coincurve`) where that backend is available.
- **RFC 6979**: `keylab.ec.rfc6979.generate_nonce` wraps the reviewed `ecdsa`
  library and is cross-checked bit-for-bit against KeyLab's own
  `rfc6979_nonce_from_digest`; both target the same RFC the C references above
  implement.
- **Official vectors**: BIP-32/39/340/341/327, RFC 6979 — see
  [tests/vectors/README.md](../tests/vectors/README.md).

These references are the authority; where KeyLab disagrees with them on a
standard input, KeyLab is wrong.

## Transaction broadcasting (M14)

KeyLab broadcasts an **already-signed** transaction via public HTTP explorer APIs
or directly over the P2P protocol. The implementations are KeyLab's own; the
methodology and endpoints are referenced below.

| Project / API | What it is / why referenced |
|---|---|
| [`laanwj/bitcoin-submittx`](https://github.com/laanwj/bitcoin-submittx) | Standalone P2P transaction submitter — the methodology `keylab.wallet.broadcast_p2p` follows (version handshake, `inv`, then `tx` on `getdata`). |
| [`petertodd/python-bitcoinlib`](https://github.com/petertodd/python-bitcoinlib) | The library KeyLab uses for P2P message serialization (`msg_version`/`inv`/`getdata`/`tx`) and transaction parsing. |
| [mempool.space REST API](https://mempool.space/docs/api/rest) | `POST /api/tx` broadcast endpoint used by `MempoolSpaceBroadcaster` (mainnet and testnet). |
| [BlockCypher API](https://www.blockcypher.com/dev/bitcoin/#transaction-api) | `POST /v1/btc/<chain>/txs/push` broadcast endpoint used by `BlockCypherBroadcaster`. |

Broadcasting pushes a pre-signed transaction and handles no keys. A **mainnet**
broadcast requires one explicit confirmation (`confirm_mainnet=True`), and signing
real-value keys must use the audited coincurve/libsecp256k1 backend — the
pure-Python ECC is non-constant-time (see [../SECURITY.md](../SECURITY.md)).
