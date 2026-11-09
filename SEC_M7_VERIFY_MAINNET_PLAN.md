# SEC_M7 — Verification pipeline + read-only mainnet linkage (PLAN, revised)

Status: **PLAN ONLY — no code yet.** The four earlier clarifications are
**CONFIRMED**: forward-feed = the §1 pipeline; **Bitcoin only**; default explorer
**mempool.space**; ECDH = (a) first-class `keylab.ec.ecdh()` (an M8 naming note).
The SECURITY.md read-only-network amendment (§5, previously acked) is **landed as
part of the M7 PR**. **Revised for the lifted project constraints (2026-11-08):**
dependencies, network access, and test skips are now permitted, so this version
uses a real HTTP client (`httpx`), an opt-in **live** integration test, and pulls
**batch verification** forward. M8 (ECDH + optimizations) is not started.

Sequence position: after M6 merged to `main` (`d714281`).

---

## 0. One-paragraph honest framing

M7 adds the ability to *fetch public chain data over the network and verify it
locally*. It adds **no** ability to sign, broadcast, custody keys, or touch a
private node. The network is a **data source only**: every cryptographic
judgement (signature valid? PoW on the header? txid matches?) is made locally by
existing `keylab.ec.*` / `keylab.encoding.*` primitives. The explorer is **never
trusted** to tell us whether something is valid — only to hand us bytes we then
check ourselves. If the explorer lies, local verification fails closed.

---

## 1. "Verification pipeline" = forward-feed (CONFIRMED)

A staged pipeline, each stage consuming the previous stage's output:

```
input (txid | raw tx hex | PSBT)
  → stage 1  PARSE          decode to a structured transaction
  → stage 2  VERIFY-SIG     recompute BIP-143/341 sighash, check each input's
                            ECDSA/Schnorr signature LOCALLY
  → stage 3  CONFIRM (opt)  fetch the confirming block header, verify its PoW and
                            that the tx's merkle path leads to the header root
  → output   REPORT         pass/fail at each stage, with the reason
```

Each stage is pure and independently testable. Stage 3 is the only networked
stage and is **optional** (`confirm=False` by default). Stages 1–2 run fully
offline on caller-supplied bytes, so the pipeline is useful **with no network at
all**; the mainnet client (§2) only feeds stage 1's input and stage 3's header.
Documented in `docs/verify_mainnet.md`: **parse → verify local signature →
confirm inclusion**.

**Not** in the pipeline: mempool policy, fee estimation, RBF/CPFP, or Script
execution beyond the sighash reduction the caller supplies ("Not a consensus
implementation", per SECURITY.md).

---

## 2. "Read-only mainnet linkage" — the narrow version, with an `httpx` client

- **Transport:** HTTPS only, via **`httpx`** (connection pooling helps batch
  fetches; cleaner exceptions than raw `urllib`). TLS **1.2+** is enforced in the
  client config: the client is built with an `ssl.SSLContext` whose
  `minimum_version = ssl.TLSVersion.TLSv1_2`, `check_hostname = True`,
  `verify_mode = ssl.CERT_REQUIRED`, passed as `httpx.Client(verify=ctx)`. There
  is **no code path** that disables verification (no `verify=False`, no
  `--insecure`). A non-`https://` URL raises a **hard error before any socket is
  opened**.
- **Method:** HTTP **GET only.** The client exposes exactly one egress method
  (`_get`); there is no POST/PUT/PATCH/DELETE anywhere, so broadcast (a POST on
  mempool.space) is **structurally impossible**, not merely disabled.
- **Endpoints:** a configurable **allow-list** of explorer base URLs; default
  `["https://mempool.space"]`. A host off the allow-list is refused. No
  self-hosted / private-node support (a consumer-app concern, out of scope).
- **Fetched:** public artifacts only — transaction (raw hex / JSON), block
  header, block txid list / merkle proof, UTXO/outspend record. **No** account,
  wallet, xpub, or address-history endpoints (privacy footgun, out of scope).
- **Sent:** the request URL and standard headers only. **No key material, no
  secrets, no PSBT contents, no local state, no user identity** — ever.
- **Trusted:** nothing from the network is a verdict. A field like
  `"status":"confirmed"` is ignored; we fetch the header and check PoW ourselves.

### Read-only enforcement is a hard boundary in the class design (§requirement 4)

`ReadOnlyExplorerClient` is designed so that read-only is **structural, not
conventional**:
- its only public verb is `get_*` methods funnelling through one private `_get`;
- it imports **no** signing/private-key/broadcast code and holds **no** key state;
- a **static test** asserts the module's source contains no `post`/`put`/`delete`/
  `broadcast`/`sendrawtransaction`/`private`/`sign` egress tokens, and that the
  only `httpx` call is a GET. The boundary is thus checked by CI, not just prose.

---

## 3. Module layout

```
src/keylab/verify/
  __init__.py          public entry points (re-exports)
  pipeline.py          Stage enum, StageResult, VerificationReport, verify()
  report.py            structured report dataclasses + to_dict()/to_json()
  batch.py             batch signature verification (§7)
  mainnet/
    __init__.py
    client.py          ReadOnlyExplorerClient: httpx, GET-only, TLS1.2+, allow-list
    mempool_space.py   mempool.space response adapter -> keylab tx/header types
    schema.py          defensive JSON schema guards (fail closed)
```

- `keylab.verify.pipeline.verify(...)` works with **zero** network when given raw
  bytes and `confirm=False`. The networked client is **injected**, so the pure
  stages never import `httpx`/`ssl`.
- `keylab.verify.mainnet.client` is the **only** module that opens a socket — the
  entire network surface to audit is one file with one GET method.
- Reuses existing crypto: `ecdsa_verify_digest`, `keylab.ec.schnorr`
  (`schnorr_verify`, `schnorr_verify_batch`), `keylab.encoding.transaction`
  sighash. **M7 writes no new crypto.** No new namespace beyond `keylab.verify`.

---

## 4. CLI — `scripts/verify_mainnet.py`

```
verify_mainnet.py tx <txid> [--confirm] [--explorer URL] [--json]   # fetch + verify
verify_mainnet.py tx --raw <hex> [--json]                           # offline, no network
verify_mainnet.py header (--height N | --hash HEX)                  # fetch header, verify PoW
verify_mainnet.py explorers                                         # print allow-list
```

Example: `verify_mainnet.py tx 4a5e1e4b…da33b --confirm --json`. Prints a
per-stage pass/fail block; exits non-zero if a non-optional stage fails. No
prompts (non-interactive).

---

## 5. SECURITY.md amendment (VERBATIM — landed in the M7 PR)

This read-only-network amendment was **acked earlier**; M7 lands it. New bullet
under **## What Keylab is not**, after the "Not a wallet" bullet:

```markdown
- **Not a network client beyond read-only verification.** `keylab.verify.mainnet`
  may perform **HTTPS GET requests to an allow-listed set of public block
  explorers** (default: `mempool.space`) to fetch **public** artifacts —
  transactions, block headers, merkle proofs, and UTXO records — **as data only**.
  Every cryptographic judgement (signature validity, proof-of-work, txid and
  merkle-root matching) is made **locally** by Keylab's own primitives; a fetched
  explorer field is never trusted as a verdict. The client enforces **TLS 1.2 or
  higher with certificate validation on** and has **no code path** to disable it.
  It performs **GET only**: it does **not** broadcast transactions, submit to a
  mempool, POST any data, transmit key material or secrets, or connect to private
  or self-hosted nodes. Signing and broadcasting remain out of scope. This is the
  **only** network capability in Keylab; the offline posture above otherwise stands.
```

---

## 6. Threat model (explicit)

| Asset / actor | Treatment |
|---|---|
| The explorer (mempool.space) | **Untrusted data source.** Hands us bytes; its verdicts, status fields, and "valid" flags are ignored. A malicious or buggy explorer can only make local verification **fail**, never falsely pass. |
| Fetched tx / header / proof | **Data to verify locally**, not trusted. Signatures re-checked against the recomputed sighash; PoW re-checked against `nBits`; merkle path recomputed to the header root; txid = double-SHA256 of the bytes. |
| TLS / network path (MITM) | TLS 1.2+ with cert validation, no disable path; `http://` refused pre-flight. A downgrade/MITM cannot present data that passes local checks for a different tx. |
| The user's keys / secrets | **Never involved.** No signing, no key input, nothing transmitted. The module has no private-key code path. |
| Rate limits / downtime | A network error surfaces as a failed CONFIRM stage with a reason, never a crash or a false pass. |

---

## 7. Batch verification (pulled into M7)

Bring batch verification into M7 because the pipeline's natural unit is "verify N
transactions / N inputs at once":
- **Schnorr/Taproot (BIP-340)**: reuse the existing `schnorr_verify_batch` —
  genuine multi-scalar batch verification, materially faster on ≥10 signatures.
- **ECDSA**: no standard single-equation batch; `keylab.verify.batch` verifies
  ECDSA inputs concurrently (thread pool over the pure `ecdsa_verify_digest`),
  and leaves the per-signature algorithmic optimisation (wNAF, Shamir, precomputed
  G) to **M8**. The pipeline calls batch verify when a block/N-tx set is checked.

Exit target: **≥1.8×** throughput on a batch of ≥10 Schnorr signatures vs
sequential, measured in `bench-smoke`, stated as a measured speedup (not a
libsecp256k1 comparison). If it cannot be justified green, it drops to M8.

---

## 8. Tests

- **Default (always-run in CI): mocked fixtures.** Captured mempool.space
  responses (tx JSON, raw hex, header, merkle proof) under
  `tests/vectors/mainnet/`, provenance pinned in `tests/vectors/SOURCES.json`
  (the repo's 40-char commit-pin + sha256 discipline). Mocked via
  `httpx.MockTransport` (or `respx`) injected into the client — **zero real
  sockets in CI**, fast and deterministic.
- **TLS/read-only enforced by construction**: unit tests assert the client
  rejects `http://` and off-allow-list hosts before any transport call; that the
  `SSLContext` is `TLSv1_2+ / check_hostname / CERT_REQUIRED`; and the **static
  no-egress test** (§2) that the source has no POST/broadcast/sign path.
- **Pipeline stages** on raw-hex vectors: good tx → all stages pass; tampered
  signature → stage 2 fails; tampered header nonce → stage 3 PoW fails.
- **Opt-in live integration (`@pytest.mark.live`)** — **permitted now, off by
  default**: fetches a *recent* block header (and a confirmed tx) from live
  mempool.space over the real TLS client and verifies PoW/signatures. Run with
  `-m live`; deselected in the standard PR jobs (like `-m 'not slow'`) so rate
  limits/downtime never flake CI, but available to catch **schema drift** when the
  explorer changes its API. A dedicated opt-in CI job (or local run) exercises it.

---

## 9. Exit criteria

- `keylab.verify.verify(raw_tx, confirm=False)` verifies a known P2WPKH/
  P2SH-P2WPKH mainnet tx's signatures **offline** from fixtures; tampered-sig and
  tampered-header fixtures fail at the correct stage.
- `ReadOnlyExplorerClient`: exactly one GET egress; static test proves no
  POST/broadcast/sign/cert-disable path.
- Header PoW: double-SHA256 of the 80-byte header `<=` target from `nBits` on a
  real header fixture.
- Batch verify: ≥1.8× on ≥10 Schnorr sigs, measured + documented.
- `@pytest.mark.live` passes against live mempool.space when selected.
- All 12 CI jobs green (mocked tests only in the default jobs); `httpx` added as a
  dependency; `-m live` deselected by default.

## 10. Risks & mitigations

- **Rate limits / downtime**: mocked tests are immune; the live test is opt-in; the
  CLI surfaces HTTP errors as a failed CONFIRM stage.
- **Schema drift**: `schema.py` fails **closed** (missing/renamed field → clear
  parse error, never a silent wrong verdict); the `@live` test catches drift early.
- **Malicious data**: local verification is the whole point — a lying explorer
  makes verification fail, not pass.
- **TLS downgrade/MITM**: no cert-disable path; `http://` refused pre-flight.
- **Dependency**: `httpx` is a well-maintained, widely-audited client; it is the
  only new dependency and lives behind the single client module.

## 11. Out of scope

Signing, broadcasting, mempool submission, wallets touching the chain, key
custody, self-hosted/private nodes, address-history/clustering, Ethereum, and the
per-signature ECC optimisations (wNAF/Shamir/precomputed-G) + first-class ECDH —
those are **M8**. **M8 not started.**

---

Awaiting ack before writing M7 code.
