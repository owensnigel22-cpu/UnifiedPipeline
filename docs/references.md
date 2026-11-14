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

## Reduced-round SHA-256 preimages (M15, Phase B)

KeyLab's 19-step context-shaping solver
(`keylab.research.sha256_reduced.context_shaping`) is a faithful Python port of
the CPU solver below; the register-window identity it shares is credited the
same way. **Reduced-round only** — no full 64-round preimage is claimed.

| Project | License | What it is / why referenced |
|---|---|---|
| [`srw/sha256-19-and-20-step-preimages-with-padding`](https://github.com/srw/sha256-19-and-20-step-preimages-with-padding) | MIT | Source of the ported `src/pre19.c` 19-step solver (a-register window + context shaping + Q-table), the published `abc` 19/20-step witnesses verified in `keylab.research.sha256_reduced.published`, and the padding-inversion technique. Context shaping credited to K. S. Basra. |
| [`kamb-code/sha256-r19-preimage`](https://github.com/kamb-code/sha256-r19-preimage) | see repo | Independent algebraic 19-round preimage work; cross-reference for the reduced-round approach. |

Honest note: a full pure-Python run of the srw *19/20-step* search is impractical
(the Q-inverse table covers only `2**(table_bits - 32)` of the range, leaving
~`2**37` chains at a Python-feasible table size; measured: 5.77M chains in ~170s
found nothing). The port is reference-correct and forward-verifying, intended for
study and for driving the reference C/CUDA solvers.

What *is* feasible in pure Python, and exercised live in the test suite:
`register_window_preimage` solves the schedule-free 8..16-round regime
deterministically, and `search_17_step_preimage` solves a 17-round instance (a
single expanded schedule word, `W_16`) by a meet-in-the-middle over two independent
register words, returning a forward-verified compression preimage in seconds. No
full 64-round preimage is attempted or claimed.

## Probabilistic & algebraic solvers (M15, Phase C)

`keylab.research.sha256_prob` models the reduced-round compression as one shared
bit circuit (`_circuit.py`, validated against the reference compression) and solves
it two ways. **Reduced-round and truncated only** — no full 64-round preimage.

| Project | License | What it is / why referenced |
|---|---|---|
| [`hirorylabo/preimage-attacks`](https://github.com/hirorylabo/preimage-attacks) | see repo | Factor-graph / belief-propagation preimage research; reference for the bit factor-graph and loopy BP approach in `belief_propagation.py`. |
| [`trevphil/cryptosym`](https://github.com/trevphil/cryptosym) | see repo | Symbolic/probabilistic hash-inversion toolkit (BP, and MILP/SAT encodings); reference for the factor-graph construction and the MILP bit-model. |

Honest note on BP: loopy belief propagation does **not** converge on, or invert,
the SHA-256 circuit — the engine is *exact on trees* (pinned against brute force in
the tests), but on the hash it is at best a weak solver for easy instances. Measured
over 5 seeds at `n_bits=64`, `max_iters=60`: one round decodes a forward-verified
truncated preimage 5/5 at `target_bits=8`, 2/5 at 16, 1/5 at 24; two rounds, 0/5.
Those results are reported, never hidden, and every decode is forward-verified.

Honest note on MILP: `sha256_milp.compression_milp(rounds)` emits a correct bit-level
0/1 model (every gate linearised; the true wire assignment satisfies all constraints
in the tests) to `.lp`/`.mps` with no solver dependency. `MILPModel.solve()` needs
the optional `milp` extra (`pulp`, bundling CBC) and, when present, returns a
forward-verified preimage for small reduced-round instances. It is a feasibility /
constraint model — **not** a differential active-S-box bound model — and only small
instances are tractable.

## Length-extension expansion (M15, Phase D)

`keylab.hashes.length_extension.length_extend(algorithm, ...)` forges
`H(secret || message || glue || append)` from `H(secret || message)` and the
original length alone, for MD5, SHA-1, SHA-256, and SHA-512. This is a property
of every plain Merkle-Damgard hash, not a weakness unique to any one; it recovers
no secret and inverts no hash. **Use HMAC, never `H(secret || message)` as a MAC.**

| Project | License | What it is / why referenced |
|---|---|---|
| [`iagox86/hash_extender`](https://github.com/iagox86/hash_extender) | BSD-3-Clause | The canonical length-extension tool (MD5, SHA-1, SHA-256, SHA-512, and more). KeyLab's `length_extend` implements the same algorithm; the per-hash constants are derived from first principles (MD5 from `sin`; SHA-512 from integer cube/square roots of the first primes), not transcribed. |

Honest note: this port is not cross-checked against a captured hash_extender run
here; its correctness is pinned to the **`hashlib` oracle** — for every supported
hash and many message lengths, the forged digest equals
`hashlib.new(algorithm, secret || forged_message).digest()` (the same guarantee
hash_extender gives). `sha256_length_extend` is retained as a thin, backward-
compatible wrapper over `length_extend("sha256", ...)`.
