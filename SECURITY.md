# Security policy and threat model

Keylab is a research and teaching library. Its cryptographic code is written
to be **readable and checkable against published test vectors**, not to
protect real keys or funds.

## What Keylab is not

- **Not constant-time.** Python big-integer arithmetic, branches on secret
  bits (double-and-add, windowed tables indexed by secret digits, early
  returns), and `pow(x, -1, n)` all leak timing. Anyone who can time or
  observe operations on a secret key may be able to recover it.
- **Not side-channel hardened.** No blinding, no memory zeroization, no
  protection against fault injection beyond the self-verification noted below.
  Python cannot reliably erase secrets from memory.
- **Not safe for real funds.** M12 adds an experimental wallet workflow that
  can retrieve test-network WIFs from an OS-native credential store, select
  UTXOs, sign and finalize supported PSBTs, preflight transactions, and
  broadcast on testnet or regtest. **M14 adds mainnet broadcasting** via public
  HTTP explorer APIs (mempool.space, BlockCypher) and direct P2P relay
  (`keylab.wallet.broadcast`); a mainnet broadcast requires **one explicit
  confirmation** per transaction and is never fired silently (the older M12
  guarded RPC path still rejects mainnet). Broadcasting pushes an **already-signed**
  transaction and handles no keys. **Signing real-value keys must use the audited
  coincurve/libsecp256k1 backend** — the pure-Python ECC is **not constant-time**
  (it can leak a secret key, see below) and must never sign real-value keys. This
  code is not audited custody. `keylab.psbt` parses,
  validates (BIP-174 rules), and re-serializes Partially Signed Bitcoin
  Transactions, and implements the BIP-174 **Signer**, **Finalizer**,
  **Extractor**, and **Combiner** roles for P2WPKH and P2SH-P2WPKH inputs
  (deterministic ECDSA partial signatures, final scriptSig/scriptWitness
  construction, final BIP-144 transaction assembly, and union of PSBTs sharing
  one unsigned transaction), for study and test-vector verification. It does
  not merge PSBTs for differing transactions; it does not handle P2WSH,
  Taproot, or multisig inputs. The M12 wallet workflow currently supports
  confirmed P2WPKH and P2SH-P2WPKH UTXOs only. The signer takes a private scalar supplied by
  the caller, uses the existing deterministic (RFC 6979, low-S) ECDSA primitive,
  verifies each signature it produces before emitting it, and never logs or
  prints key material. The finalizer **consumes existing signatures only** -- it
  never creates a signature, never alters the unsigned transaction, verifies
  each partial signature before finalizing, and leaves unrelated inputs and
  unknown fields untouched. The extractor performs **no cryptography** -- it
  assembles the final transaction from already-finalized fields without signing,
  verifying, or altering transaction contents, and returns bytes only (it does
  not broadcast). The combiner also performs **no cryptography** -- it unions
  key-value pairs across PSBTs that share one unsigned transaction, interprets
  no value, and never mutates its inputs.
- **Network calls have distinct trust and safety boundaries.** `keylab.verify.mainnet`
  may perform **HTTPS GET requests to an allow-listed set of public block
  explorers** (default: `mempool.space`) to fetch **public** artifacts --
  transactions, block headers, merkle proofs, and UTXO records -- **as data only**.
  Every cryptographic judgement (signature validity, proof-of-work, txid and
  merkle-root matching) is made **locally** by Keylab's own primitives; a fetched
  explorer field is never trusted as a verdict. The client enforces **TLS 1.2 or
  higher with certificate validation on** and has **no code path** to disable it.
  It performs **read-only GETs only** and does not broadcast or transmit private
  keys. Separately, `keylab.verify.node.BitcoinRPCClient` sends JSON-RPC requests
  to a configured Bitcoin Core node for wallet state queries, mempool
  preflight, and guarded raw-transaction submission. The client warns when a
  non-loopback endpoint uses plaintext HTTP because RPC credentials and
  transaction data are not encrypted; remote RPC must use HTTPS or an
  operator-managed secure tunnel. The M12 broadcast APIs reject mainnet and
  require explicit test-network confirmation, verify the node's reported chain,
  recheck selected outputs, and require a passing `testmempoolaccept` response
  before sending once. A preflight result is not a guarantee of later
  confirmation, and a send timeout can leave acceptance uncertain. Do not
  retry automatically or treat this path as suitable for real funds.
- **Not a consensus implementation.** `keylab.encoding.transaction` computes
  BIP-341 and BIP-143 (SegWit v0) signature hashes for study; it does not
  validate transactions, execute Script, or process `OP_CODESEPARATOR` (the
  caller supplies the reduced scriptCode).
- **Not a source of real-wallet mnemonics.** `keylab.mnemonic` implements
  BIP-39 generation and recovery for study and testing. It draws entropy from
  `secrets`, but the process is not audited, does not erase the entropy,
  mnemonic, or seed from memory, and runs in non-constant time. **Do not use a
  generated mnemonic to hold funds.** Create real seed phrases with mature,
  audited wallet software, offline, on hardware you trust.
- **Not independently audited.**

For any real secret key, use a reviewed implementation such as
[libsecp256k1](https://github.com/bitcoin-core/secp256k1) (for example via
`coincurve`) or Bitcoin Core.

## What Keylab does provide

- Behaviour checked against official vectors: BIP-32 (vectors 1-5), BIP-39
  (Trezor reference set), BIP-340 (vectors 0-18), BIP-327 KeyAgg/KeySort,
  BIP-341 wallet vectors, BIP-49/84/86, BIP-173 and BIP-350; RFC 6979 and
  ECDSA public-key recovery are cross-checked against libsecp256k1.
- Differential tests against libsecp256k1 for multiplication, addition,
  doubling, SEC1/x-only encoding, BIP-340 and ECDSA signatures.
- Strict input validation: scalars must be in `[1, N-1]`, points must be on
  the curve, extended keys are rejected for every BIP-32 vector-5 defect.
- BIP-340 signing re-verifies each signature before returning it, which
  catches some computation faults (it is not a complete fault-attack defence).
- **User-supplied secrets are never displayed without an explicit flag.**
  `keylab wif-derive` and `keylab-advanced --wif` show public data only and
  reveal the private scalar only with `--show-private`. Benchmarks never
  print scalars, keys, WIFs, or signatures.
- **Teaching traces use fixed, public demo keys.** `keylab-advanced` traces
  (ECDSA, BIP-340, RFC 6979, nonce reuse) print intermediate values such as
  nonces and signatures for a hard-coded demo key so the arithmetic can be
  followed. That key is public and must never hold funds.

Cryptographic assumptions and implementation notes are in
[docs/architecture.md](docs/architecture.md).

## Threat model for intended use

| Asset | Intended handling |
|---|---|
| Published test vectors and seeded benchmark corpora | Public; safe to print and share |
| Throwaway keys created for experiments | Acceptable, on a machine you control |
| M12 OS-keyring testnet/regtest WIFs | Test material only; accessible to the running process and not guaranteed to be erased from memory |
| M12 node RPC credentials and transactions | Treat as sensitive; remote plaintext HTTP exposes credentials and transaction contents |
| Any key that controls real value | **Use the audited coincurve/libsecp256k1 backend only.** The pure-Python ECC is non-constant-time and must never sign real-value keys; mainnet broadcasting requires one explicit confirmation |

The optional `wallet` extra enables `KeyringProvider`. It refuses non-native
keyring backends and has no plaintext-file fallback, but OS credential-store
protections vary and do not protect a key from a process authorized to retrieve
it. Python does not guarantee zeroization. `HardwareSigner` defines a PSBT
handoff interface only; vendor device transport and on-device transaction
review are not implemented in M12.

Research modules (`halving`, `quartic`, `division_polynomials`, nonce-reuse
and BIP-32 parent-recovery demonstrations) illustrate known mathematics. They
do not weaken secp256k1: halving a public key yields a point whose discrete
logarithm is just as unknown, and the recovery demonstrations require the
specific leaked secrets their docstrings name (a reused nonce, or a
non-hardened child private key plus the parent chain code).

The `keylab.research.ecdlp` package is also educational, and like the rest of
`keylab.research.*` it exists for study only — none of it is selected by
`scalar_mult`, signing, or verification. `backward_double_add` reverses the
double-and-add ladder from a public key; this is **exactly the ECDLP**, costs
`2**bit_length(k)`, and only resolves small, explicitly supplied scalars — it has
no advantage over brute force and no bearing on real keys. Past depth 18 it emits
a `DeepTraversalWarning` and proceeds (deep traversal is permitted with a warning,
not capped). `halve_m` collapses *m* repeated halvings of a single point into one
scalar multiplication; this is a convenience that does **not** apply to the
branching traversal and gives no ECDLP shortcut.

`kangaroo` is Pollard's kangaroo in its two-role **distinguished-point** form: it
solves the *bounded-interval* ECDLP in ~`O(2*sqrt(width))` hops, with table memory
bounded by the distinguished-point density, and a run can be checkpointed and
resumed. The distinguished-point variant is **not faster** than a single moving
trap — the asymptotics are identical; it only bounds memory and allows resuming.
Passing the full group `[0, N-1]` makes it a full-group ECDLP attempt needing
~`2**129` hops: a measured 60-second run reaches about `2**-109` of that work and
stops. **This is a wall, not a slowdown** — no budget, number of walkers, or
amount of patience changes the exponent. Every candidate these tools return is
forward-verified (`k*G == Q`) before it is reported.

## Reporting a vulnerability

If you find a correctness bug (a mismatch with a BIP, RFC, or libsecp256k1),
please open an issue with the inputs that reproduce it. If you believe a bug
could mislead someone into an unsafe use, mark the report as security
relevant and describe the impact; please do not include real private keys.
