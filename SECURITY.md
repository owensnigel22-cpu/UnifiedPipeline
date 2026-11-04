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
- **Not a wallet.** There is no key storage, encryption at rest, coin
  selection, fee logic, or transaction broadcast. `keylab.psbt` parses,
  validates (BIP-174 rules), and re-serializes Partially Signed Bitcoin
  Transactions, and implements the BIP-174 **Signer**, **Finalizer**, and
  **Extractor** roles for P2WPKH and P2SH-P2WPKH inputs (deterministic ECDSA
  partial signatures, final scriptSig/scriptWitness construction, and final
  BIP-144 transaction assembly), for study and test-vector verification only. It
  does **not** broadcast a transaction, combine or merge PSBTs; it does not
  handle P2WSH, Taproot, or multisig inputs; and it is not production wallet
  software. The signer takes a private scalar supplied by the caller, uses the
  existing deterministic (RFC 6979, low-S) ECDSA primitive, verifies each
  signature it produces before emitting it, and never logs or prints key
  material. The finalizer **consumes existing signatures only** -- it never
  creates a signature, never alters the unsigned transaction, verifies each
  partial signature before finalizing, and leaves unrelated inputs and unknown
  fields untouched. The extractor performs **no cryptography** -- it assembles
  the final transaction from already-finalized fields without signing,
  verifying, or altering transaction contents, and returns bytes only (it does
  not broadcast).
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
| Any key that controls real value | **Out of scope.** Do not load it into Keylab |

Research modules (`halving`, `quartic`, `division_polynomials`, nonce-reuse
and BIP-32 parent-recovery demonstrations) illustrate known mathematics. They
do not weaken secp256k1: halving a public key yields a point whose discrete
logarithm is just as unknown, and the recovery demonstrations require the
specific leaked secrets their docstrings name (a reused nonce, or a
non-hardened child private key plus the parent chain code).

The `keylab.research.ecdlp` package is also educational. `backward_double_add` reverses
the double-and-add ladder from a public key; this is **exactly the ECDLP**, costs
`2**bit_length(k)`, and only resolves small, explicitly supplied scalars — it has
no advantage over brute force and no bearing on real keys. `kangaroo` (Pollard's
kangaroo) solves the *bounded-interval* ECDLP in ~`O(sqrt(width))`; a full 256-bit
key would need ~`2**128` hops. Neither is selected by `scalar_mult`, signing, or
verification, and every candidate they return is forward-verified (`k*G == Q`).

## Reporting a vulnerability

If you find a correctness bug (a mismatch with a BIP, RFC, or libsecp256k1),
please open an issue with the inputs that reproduce it. If you believe a bug
could mislead someone into an unsafe use, mark the report as security
relevant and describe the impact; please do not include real private keys.
