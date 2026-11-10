# M12 Plan: Node Connectivity, Key Handling, and Transaction Broadcasting

**Status:** Approved and implemented on `docs/m12-broadcast-plan`; project-owner
review is pending. The implementation is limited to testnet/regtest, with
mainnet broadcast rejected in the wallet API and guarded node RPC method.

**Prepared against:** fetched `origin/main` commit
`152f0e64554a8c0e1f75afc485b2c10156d1a758`. The owner reported M11 complete;
the commit was fetched and verified as `docs: complete M11 release
preparation` before implementation began.

## Objective and boundaries

Plan a narrowly scoped, test-network-only transaction workflow that queries a
Bitcoin Core node, finds confirmed UTXOs for an explicit descriptor, constructs
a PSBT, obtains a signature from a software or hardware signer, checks the
finished transaction with the node, and broadcasts it only on testnet or
regtest.

The existing `ReadOnlyExplorerClient` remains read-only and continues serving
the M7 verifier. Wallet state queries will use a new node client; they will not
change M7's trust model or reinterpret explorer data as verified state.

This milestone is research and teaching functionality. It does not make
Keylab suitable for real funds. M12 must not implement mainnet broadcasting,
even when a caller supplies the test-network confirmation flag. Mainnet RPC
configuration may be used for read-only calls, but the broadcast interface
must reject a node whose reported chain is `main`.

## Verified starting points at plan preparation

- `src/keylab/verify/mainnet/client.py` contains the GET-only HTTPS
  `ReadOnlyExplorerClient`.
- `src/keylab/encoding/transaction.py` parses and serializes transactions and
  computes sighashes; its module documentation explicitly says it does not
  build or broadcast transactions.
- `src/keylab/psbt/` contains BIP-174 model, parse, validate, serialize, sign,
  finalize, extract, and combine code. The existing signer/finalizer scope is
  P2WPKH and P2SH-P2WPKH. A general PSBT creator and full wallet lifecycle are
  not documented as implemented.
- `src/keylab/psbt/signer.py` accepts a Python private scalar and performs
  signing through Keylab's Python secp256k1 implementation. It is variable
  time; a keyring lookup does not make that signing path constant time.
- `pyproject.toml` already has `httpx` as a core dependency, and the optional
  `crypto`, `crypto-alt`, and `fast` extras. There is no `keyring` dependency
  or `keylab.wallet`/`keylab.verify.node` package in the inspected tree.
- At plan preparation, `SECURITY.md` stated that Keylab had no key storage,
  coin selection, or transaction broadcast. It has now been updated alongside
  the M12 implementation to document the test-network-only scope and risks.

## Proposed component layout

```text
CLI / future wallet facade
        │
        ├── keylab.verify.node.BitcoinRPCClient ── Bitcoin Core JSON-RPC
        │      read state, descriptor scans, preflight, broadcast
        │
        └── keylab.wallet.tx ── UTXO scanner ── bounded coin selector
                 │                          │
                 ├── PSBT creator/updater ──┘
                 ├── SoftwareSigner (test-only KeyringProvider)
                 └── HardwareSigner protocol (PSBT in / PSBT out)
```

Keep the node transport, wallet/key interfaces, UTXO policy, coin selection,
PSBT construction, and CLI as separate units. The transaction flow should
depend on protocols/interfaces so tests can substitute fake nodes and signers.
No wallet/key module may be imported by the read-only M7 verification path.

### Node RPC client — `keylab.verify.node`

Add a synchronous `BitcoinRPCClient` built on the existing `httpx` dependency.
It should use `httpx.Client` pooling with bounded connection counts and an
explicit connect/read/write/pool timeout. It should support JSON-RPC calls for
`getblockchaininfo`, `gettxout`, `getrawtransaction`, `testmempoolaccept`, and
`sendrawtransaction`; add `scantxoutset` for descriptor scans. RPC method
wrappers should validate request parameters and parse typed results rather
than exposing unvalidated JSON throughout the wallet code.

Configuration should bind an endpoint to an expected network (`regtest`,
`testnet`, or `mainnet`). After connection and before every broadcast, compare
the configured network to `getblockchaininfo.chain`; reject mismatches. Bitcoin
Core reports network identifiers such as `main`, `test`, and `regtest`, so the
adapter must normalize these identifiers explicitly and reject unknown values.
Never infer the network from an address prefix alone.

Prefer Bitcoin Core's local `.cookie` authentication. Support explicit HTTP
Basic authentication only as a compatibility option. Keep credentials out of
URLs, logs, exception text, metrics, and command-line arguments. Bitcoin Core
documents that RPC authentication does not encrypt HTTP traffic and warns
against public-Internet exposure; remote use must therefore require HTTPS
termination or an operator-managed VPN/SSH tunnel, with the client connecting
through that protected channel. Do not suggest `rpcallowip` plus an open
public port as a secure deployment.

Retry only idempotent reads under a small, explicit retry policy. Do not
automatically retry `sendrawtransaction`: after a timeout the client may not
know whether the node accepted the transaction. Return an indeterminate
broadcast result and require a separate txid/mempool lookup before another
operator action. Bound concurrency to avoid exhausting node HTTP connections.

### Secure key and signer interfaces — `keylab.wallet.keys`

Define a `KeyProvider` protocol that returns a short-lived key handle or
signing capability, not a general-purpose secret export API. The proposed
`KeyringProvider` should access the OS credential store through the optional
`keyring` package. Key aliases and account metadata may be stored as ordinary
configuration; private key material must never be written to project files,
plaintext configuration, logs, shell history, or command arguments.

Fail closed when `keyring` has no usable OS-backed backend or selects a known
fail/insecure backend. Do not silently fall back to a plaintext file, an
environment variable, or an alternate backend. Require explicit setup and
backend diagnostics. Test with an in-memory fake backend; never use a user's
real credential store in tests.

Document the limits: a keyring protects stored credentials according to the
OS backend, but a Python process that can retrieve a key can expose it in
memory; Python does not guarantee memory zeroization; keyring backend policy
and access control vary by OS. In particular, keyring's own documentation
states that some backends may allow the same Python executable to read secrets
without another prompt. Therefore the software-keyring signer is for synthetic
testnet/regtest keys only and must not be described as audited custody.

Define a `HardwareSigner` protocol around PSBT input and PSBT output (for
example, `sign_psbt(psbt_bytes, network) -> psbt_bytes`). It must provide no
private-key export method. A future Trezor/Ledger adapter may use a vendor
transport or Bitcoin Core external-signer workflow, but this plan does not add
vendor dependencies or device code. The device must display transaction
details and require user confirmation; host-side validation remains required.

### UTXO discovery and selection — `keylab.wallet.utxo`

Accept a checksummed output descriptor (or a validated address converted to an
`addr(...)` descriptor) as the scan target. The preferred Core source is
`scantxoutset`, which scans the node's current UTXO set for descriptors and
returns the chain height, best block, script, amount, descriptor, and output
height. Treat this RPC as version-sensitive/experimental and check method
availability. `gettxout` accepts a known outpoint; it cannot enumerate all
outputs for an address. Recheck every selected outpoint with
`gettxout(..., include_mempool=true)` before PSBT signing and immediately
before broadcast. The first version should support confirmed UTXOs only and
must not claim that this scan includes unconfirmed receipts; Core's RPC
documentation describes chain and mempool state as time-sensitive.

Do not treat an arbitrary public indexer as authoritative. An indexer backend
would require a separate explicit trust/configuration contract, response
validation, provenance, and its own tests.

Implement a bounded Branch-and-Bound selector (or document and justify an
equivalent) with integer satoshi accounting. Inputs include target amount,
fee rate, script-type weight estimates, change creation/future-spend cost,
dust thresholds, and an explicit search-node budget. Return selected outpoints,
fee estimate, change amount, waste score, and search status. If the bounded
search finds no match, use a specified fallback or return a typed failure;
never silently exceed the budget or invent a fee. Make rounding from Core's
BTC-denominated JSON amounts exact (for example, parse decimal values with
`Decimal`) and reject amounts outside Bitcoin monetary bounds.

### PSBT creation, signing, and broadcast — `keylab.wallet.tx`

Build an unsigned transaction and PSBT with the existing transaction and PSBT
types where they fit; add a clearly named creator/updater if current APIs do
not cover construction. The first supported scope should be explicitly
limited to the script types covered by the current signer and finalizer
(P2WPKH and P2SH-P2WPKH), subject to an implementation audit of all required
PSBT UTXO and derivation fields. Do not imply support for P2WSH, Taproot,
multisig, legacy inputs, arbitrary descriptors, or every BIP-174/BIP-370
version until each is implemented and tested.

The user must review exact recipients, amounts, fee, change destination, and
network before signing. Treat all received PSBT fields and node/indexer data as
untrusted input. Validate all prevouts, scripts, amounts, fee bounds, sighash
types, and signer-to-input matches. Use a hardware signer where possible; the
existing Python PSBT signer is variable-time and exposes a key to the host.

For broadcast: (1) require explicit confirmation; (2) verify node network and
fresh selected outpoints; (3) finalize and extract; (4) validate the complete
transaction and expected txid locally; (5) call `testmempoolaccept`; (6) if
accepted, display a final summary and require a separate explicit broadcast
action; (7) call `sendrawtransaction` once; (8) report the node response or an
indeterminate state without automatic resubmission. Mempool preflight is a
point-in-time policy check, not a guarantee of future relay or confirmation.

### Test-network interlock — mandatory design

1. Default network configuration is `regtest`; tests use regtest or mocked RPC
   only. A separately opted-in testnet integration may be marked `live`.
2. No M12 command or API can broadcast when `getblockchaininfo.chain == "main"`.
   The confirmation flag does not override this prohibition.
3. Every broadcast requires a deliberate CLI flag such as
   `--i-am-on-testnet` (or a documented equivalent environment variable) and
   an independently configured expected network of `testnet` or `regtest`.
4. At call time, the client must verify that the node-reported chain agrees
   with configuration. A mismatch, unknown chain, missing confirmation, or
   failed check prevents `sendrawtransaction` from being called.
5. Tests include negative controls proving that a mainnet RPC response cannot
   reach the send method even when the flag is present. Unit tests use a mock
   transport that records RPC calls; only regtest integration tests may send
   transactions to a real node.
6. A future mainnet-broadcast proposal requires a new explicit owner decision,
   a separate threat review, updated security policy, and a distinct test
   strategy. It is outside M12.

## Dependency proposal and policy

| Need | Proposed dependency | Policy |
|---|---|---|
| JSON-RPC HTTP transport and pooling | Existing `httpx>=0.27` core dependency | Reuse; do not add `python-bitcoinrpc` or another transport package unless a demonstrated Core protocol gap requires it. |
| OS credential store | Candidate optional extra `[wallet] = ["keyring>=25.7,<26"]` | Optional only; verify supported OS backends, Python versions, dependency license, fail-closed detection, and CI install matrix before adding. |
| Transaction/PSBT data | Existing `keylab.encoding.transaction` and `keylab.psbt` | Prefer reuse; add only the missing creator/updater operations and tests. |
| Independent Bitcoin serialization/RPC cross-check | `python-bitcoinlib` is not proposed as a runtime dependency | Its upstream describes a low-level library and RPC support; its repository license is LGPL-3.0-or-later. Before any adoption, review license compatibility, maintenance/API fit, consensus-validation limitations, and whether differential test-only use is sufficient. Do not copy code. |
| Trezor/Ledger device communication | None in initial M12 plan | Implement only a vendor-neutral PSBT signer protocol first. Select a vendor SDK and optional extra only after device/model, supported script types, signing UX, license, and platform matrix are approved. |

`bitcoinrpc` is not needed for the first design because the project already has
`httpx` for pooled HTTP. Bitcoin Core JSON-RPC is a small transport contract;
using the existing HTTP client keeps connection timeouts and TLS policy in one
place. Keep the RPC interface behind a protocol so a transport dependency can
be reconsidered if a tested requirement justifies it.

## Candidate file-level implementation scope (after acknowledgment)

| Candidate file | Planned responsibility |
|---|---|
| `src/keylab/verify/node/__init__.py` | Public node-client exports and typed RPC errors |
| `src/keylab/verify/node/client.py` | `BitcoinRPCClient`, HTTP pool, timeout/auth/config, network checking, RPC wrappers |
| `src/keylab/verify/node/models.py` | Network config, chain info, outpoint/UTXO and RPC result models |
| `src/keylab/wallet/__init__.py` | Wallet API boundary |
| `src/keylab/wallet/keys.py` | KeyProvider, KeyringProvider, HardwareSigner protocol; no raw-file store |
| `src/keylab/wallet/utxo.py` | Descriptor scan, exact amount conversion, gettxout rechecks |
| `src/keylab/wallet/coinselect.py` | Bounded BnB selector, fee/waste models, typed budget outcome |
| `src/keylab/wallet/tx.py` | PSBT creation/update, review model, sign/finalize/preflight/broadcast orchestration |
| `src/keylab/cli.py` or a dedicated wallet CLI module | Explicit network, confirmation, dry-run, and broadcast subcommands |
| `pyproject.toml` | Optional `wallet` extra only after dependency review |
| `SECURITY.md` | Required policy update before any M12 key handling/broadcast is merged or enabled |
| `docs/coordination/SECURITY_MODEL.md`, `docs/architecture.md`, `docs/coordination/PROJECT_STATUS.md` | Update verified architecture, threat model, and capability status after implementation exists |
| `tests/test_node_rpc.py`, `tests/test_wallet_keys.py`, `tests/test_wallet_utxo.py`, `tests/test_wallet_coinselect.py`, `tests/test_wallet_tx.py` | Unit, failure-path, security-interlock, property, differential and regtest coverage |
| `tests/integration/test_wallet_regtest.py` (or repository-equivalent) | Isolated `bitcoind -regtest` lifecycle tests; no public-chain broadcasts |

This list is a proposal; final paths may change after owner acknowledgment and
inspection of the current CLI/test organization. Do not edit `SECURITY.md` to
claim new functionality until it exists, but make the policy update a required
pre-merge gate for any feature that introduces it.

## Implementation record

The approved implementation is delivered on this branch in five commits.
`BitcoinRPCClient` uses existing `httpx`, `.cookie` or explicit Basic auth,
timeouts, pooling, and a warning for remote plaintext HTTP. Wallet key storage
is optional through the `wallet` extra and accepts test-network compressed WIFs
only; `HardwareSigner` is an interface without device transport. UTXO scanning
accepts specialized single-key P2WPKH and P2SH-P2WPKH descriptors, and coin
selection is a bounded BnB search with explicit completion state. The PSBT
workflow uses existing Keylab signer/finalizer/extractor components, rechecks
outpoints, preflights, and sends once after explicit confirmation. `Network`
rejects mainnet before RPC activity.

The current milestone does not add a wallet CLI, a live `bitcoind` integration
test, vendor hardware communication, or support for other script families.
The regtest integration test mocks RPC calls. These are deliberate scope limits
for this implementation and should not be read as future features already
delivered.

## Security model and risks

### Assets and trust boundaries

- Private key bytes, seed-derived secrets, and keyring/RPC credentials are
  sensitive. No test fixture may contain a real user's key.
- Node RPC is privileged control of the node and possibly its wallet/process
  filesystem. Treat a compromised/misconfigured RPC server as hostile.
- UTXO and fee data can be stale or malicious, especially through a remote
  indexer. Verify script/amount/outpoint consistency and show the exact
  transaction summary before signing.
- A PSBT is a request to authorize a transaction, not proof that it is safe.
  A device or user must review recipients, amounts, fee, and network.
- Broadcast is an irreversible external side effect once peers relay or miners
  confirm the transaction. `testmempoolaccept` does not reserve inputs or
  guarantee later acceptance.

### Required controls and accurate warnings

- No private key in plaintext files, CLI arguments, logs, diagnostics, crash
  reports, benchmark output, or checked-in fixtures.
- No implicit `auto` backend for key storage. Require a verified OS keyring
  backend or hardware signer; fail closed otherwise.
- No raw RPC credentials in endpoint URLs; prefer cookie auth for local nodes.
- No public-Internet Bitcoin Core RPC exposure. Remote connections require a
  protected channel because Core's RPC HTTP auth alone is not encrypted.
- Clear key material references promptly where possible, but state that Python
  cannot guarantee secret erasure or constant-time execution.
- Explicit dry-run is the default. Separate review/sign and broadcast actions.
- Mainnet broadcast is unavailable by code invariant throughout M12.
- Update `SECURITY.md` to disclose that the suite can retrieve/store test keys
  and broadcast test-network transactions, describe the keyring and host
  process risks, explain RPC authority and network restrictions, and restate
  that Keylab is unaudited, variable-time, and unsuitable for real funds.

## Validation and acceptance plan

### Unit and property tests

- RPC request IDs, JSON-RPC errors, cookie/basic auth, timeout classes,
  connection reuse, response bounds, malformed payloads, and secret redaction.
- Chain mapping for `main`, `test`, and `regtest`; mismatched/unknown chains
  always fail closed.
- Exact satoshi conversion, descriptor validation, stale/unknown/spent UTXOs,
  duplicate outpoints, amount/range limits, dust and fee bounds.
- BnB correctness against exhaustive search on small synthetic sets; node
  budget honored exactly; compare selected input totals/fees with a trusted
  reference on deterministic cases.
- PSBT serialize/parse round trips, existing official vectors, invalid
  prevouts, wrong signer key, unsupported script types, altered outputs,
  malformed partial signatures, fee tampering, and final transaction/txid
  checks.
- Explicit assertion that `sendrawtransaction` is never called for mainnet,
  a network mismatch, missing confirmation, invalid testmempoolaccept result,
  or failed local checks.
- Keyring tests use fake test backends; reject fail/insecure backends. Hardware
  protocol tests assert only PSBTs and public metadata cross the interface.

### Integration and regression

- Add an isolated regtest integration job with a private temporary data
  directory and no public peer exposure; mine test coins, scan a descriptor,
  construct/sign/finalize a small supported PSBT, run `testmempoolaccept`, and
  broadcast to regtest.
- Testnet integration is opt-in, marked `live`, requires explicit testnet
  configuration and the confirmation flag, and uses valueless synthetic test
  keys. It is never part of default CI.
- A mocked mainnet negative test must prove no network send call is possible.
- Run the full existing suite to verify no change to M7 read-only verification,
  PSBT behavior, ECDSA/Schnorr paths, and no default network side effects.
- Document Bitcoin Core versions tested, RPC API differences, OS/backend
  matrix, and unsupported script/address types.

### Exit gates

1. Owner acknowledges this plan and selects which parts of M12 are in scope.
2. Dependency, license, OS keyring behavior, RPC authentication, and chain
   guard design are approved.
3. First implementation PR is limited to node reads and typed RPC tests; no
   signing/broadcast is enabled until key safety and test-network gating pass.
4. The security policy update is included before any key-handling or broadcast
   feature is merged or advertised.
5. Regtest and negative mainnet tests pass; no claim of production readiness is
   made.

## Recommended implementation order after acknowledgment

1. Node RPC protocol/client with read-only methods and mocked transport tests.
2. Chain-identity validation, credential handling, and node threat-model docs.
3. Descriptor-based confirmed-UTXO scan and stale-outpoint checks.
4. Bounded coin-selection model and differential/exhaustive tests.
5. PSBT creator/update path for existing supported input types; review screen
   and software/hardware signer protocols.
6. Regtest-only testmempoolaccept and broadcast behind the enforced
   interlock; add negative mainnet tests and update `SECURITY.md` in the same
   implementation series before the feature is enabled.
7. Full regression, dependency/OS matrix, security review, and only then
   project-owner decision on any follow-on scope.

## References

- [Bitcoin Core JSON-RPC interface and security guidance](https://github.com/bitcoin/bitcoin/blob/master/doc/JSON-RPC-interface.md)
- [Bitcoin Core PSBT workflow and RPCs](https://github.com/bitcoin/bitcoin/blob/master/doc/psbt.md)
- [BIP-174: Partially Signed Bitcoin Transaction Format](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
- [Bitcoin Core `scantxoutset` RPC reference](https://developer.bitcoin.org/reference/rpc/scantxoutset.html)
- [Python keyring documentation and security considerations](https://keyring.readthedocs.io/en/stable/)
- [python-bitcoinlib upstream repository](https://github.com/petertodd/python-bitcoinlib) and [license](https://github.com/petertodd/python-bitcoinlib/blob/master/LICENSE)

