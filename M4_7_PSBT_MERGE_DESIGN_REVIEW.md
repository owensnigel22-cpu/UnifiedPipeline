# M4.7 — PSBT "Merge" Design Review

**Status:** DESIGN REVIEW / PLANNING ONLY. No code, no PR, no implementation.
**Repository state at review:** `main = 1073caa` (M4.0–M4.6 merged); no `merge`
module exists; only open PR is the deferred Dependabot #3.
**Question posed:** should M4.7 mean (A) additional BIP-174 v0 merge behavior,
(B) BIP-370 / PSBT v2 support, or (C) another narrowly-scoped workflow?

---

## 1. Existing capabilities

`keylab.psbt` already implements, for PSBT **v0** (BIP-174), the following roles,
all against official vectors with byte-exact or spec-faithful oracles:

| Role (BIP-174) | API | Status |
|---|---|---|
| **Parser** | `deserialize`, `parse` | structural parse, duplicate/canonical/truncation rules |
| **Validator** | `validate` | BIP-174 semantic rules; unknown keys preserved |
| **Serializer** | `serialize` | byte-exact re-serialization |
| **Signer** | `sign`, `sign_input`, `signable_inputs` | P2WPKH, P2SH-P2WPKH; deterministic ECDSA partial sigs |
| **Input Finalizer** | `finalize`, `finalize_input`, `is_finalized` | final scriptSig/scriptWitness, redundant-field removal |
| **Transaction Extractor** | `extract`, `extract_transaction` | final BIP-144 tx; `serialize_transaction` added to the single tx model |
| **Combiner** | `combine` | **union of PSBTs sharing one unsigned transaction** |

Supporting: `keylab.encoding.transaction` (single transaction model;
`parse_transaction` / `serialize_transaction`, BIP-143 sighashing), one PSBT
model (`Psbt` / `PsbtMap` / `KeyPair`).

**The decisive fact:** in BIP-174, *combining and merging are the same
operation*. BIP-174 defines exactly six roles — Creator, Updater, Signer,
Combiner, Input Finalizer, Transaction Extractor. There is **no separate
"Merger" role.** The Combiner *is* the mechanism that merges multiple parties'
PSBTs for one transaction, and M4.6 delivered it (including the official
Combiner worked-example vector).

---

## 2. Gap analysis

Answering research question 2 — "what meaningful functionality remains that
could legitimately be called *merge*" — there are three distinct buckets, and
only one of them is genuinely new:

1. **BIP-174 v0 "merge" = already delivered.** There is no additional v0 merge
   behavior beyond the Combiner. A second v0 "merge" entry point would duplicate
   `combine`, which the Master Operating Directive explicitly forbids ("Never
   create duplicate implementations"). **Gap: none.**

2. **BIP-370 / PSBT v2 "merge" = genuinely new, genuinely large.** PSBT v2
   removes the global unsigned transaction and instead stores the transaction
   skeleton as PSBT fields: global tx-version, input/output counts, fallback
   locktime, and a tx-modifiable flag; per-input previous-txid / output-index /
   sequence / required-locktimes; per-output amount / script. Because the tx is
   assembled *from the PSBT fields themselves*, v2 enables combining PSBTs that
   **contribute different inputs and outputs** — the thing people usually mean by
   "merge" beyond v0 (coordinated multi-party transaction construction,
   PayJoin/coinjoin-style flows). **Gap: the entire v2 model** — a second PSBT
   version with its own field set, serialization, validation, and role
   semantics. This is not a single milestone-sized step.

3. **BIP-174 v0 roles not yet implemented (not "merge").** The **Creator** and
   **Updater** roles are the only v0 roles KeyLab does not yet have. The Updater
   programmatically adds witness/non-witness UTXO, redeem/witness scripts,
   BIP-32 derivations, and sighash type to a PSBT (today the tests hand-build
   those records). This is legitimately useful and narrowly scoped, and it
   *completes* the v0 role set — but it is an **Updater**, not a "merge." **Gap:
   real, but mis-named by the M4.7 label.**

---

## 3. Candidate definitions

- **(A) Additional BIP-174 v0 merge behavior.** *Rejected.* The v0 merge is the
  Combiner (M4.6). Nothing of substance remains; implementing "merge" here would
  duplicate `combine`.

- **(B) BIP-370 / PSBT v2 support.** *Valid and standards-defined*, and the only
  interpretation under which "merge" means something the combiner cannot already
  do. But it is a large, multi-part effort (new v2 model, field set,
  serialization, validation, and v2-aware signer/finalizer/extractor
  interactions, plus the v0↔v2 conversion question). It is really an **M5.x
  track**, not a single "M4.7 merge" step.

- **(C) Another narrowly-scoped workflow.** The best-defined narrow option is the
  **BIP-174 Updater role** (v0): fill UTXO/script/derivation/sighash fields
  programmatically. It is a clean, vector-checkable, single-milestone unit and a
  natural precursor to wallet workflows — but it should be named **"M4.7
  Updater,"** not "merge."

---

## 4. Standards references

- **BIP-174** (Partially Signed Bitcoin Transaction Format, v0): defines the six
  roles Creator / Updater / Signer / Combiner / Input Finalizer / Transaction
  Extractor. The Combiner section is the authority for v0 merging; there is no
  "Merger." (Pinned in the repo at commit `24e96e8…`.)
- **BIP-370** (PSBT Version 2): defines the v2 model that stores the transaction
  skeleton as PSBT fields (global tx-version, input/output counts, fallback
  locktime, tx-modifiable flag; per-input prevout/index/sequence/locktimes;
  per-output amount/script) and a `PSBT_GLOBAL_VERSION` of 2. Exact field
  numbers to be pinned from the spec at implementation time. This is the only
  standard under which "merge beyond combine" exists.
- **BIP-143 / BIP-144** (already used): witness-v0 sighash and transaction
  serialization — unchanged by this decision.

---

## 5. Risks

- **Duplicate-implementation risk (A):** a v0 "merge" would shadow `combine`,
  violating the directive and confusing the API. High risk, no benefit.
- **Scope-explosion risk (B):** BIP-370 introduces a *second* PSBT
  representation. Done carelessly it would either (i) fork the `Psbt` model into
  two parallel representations — directly against the "one PSBT model" rule — or
  (ii) force an invasive refactor of the existing v0 roles. It needs its own
  planning milestone(s) and an explicit "do we support two PSBT versions?"
  decision before any code.
- **Mis-naming risk (C):** shipping an Updater under the label "merge" would
  leave the roadmap and docs inconsistent with BIP terminology and mislead future
  readers about what exists.
- **Correctness-oracle risk:** v0 options have official vectors; a bespoke
  "merge" would have none (benchmarks never override correctness — directive).
  BIP-370 has vectors, but only once the v2 model exists to run them against.

---

## 6. Recommended direction

**Do not implement a milestone called "PSBT merge."** The v0 merge is already
shipped as the Combiner (M4.6); there is no well-defined, non-duplicative "merge"
left within BIP-174 v0. "Merge" should be **renamed/retired** as a label.

Concretely, split the intent into two clearly-named tracks and pick per your
priorities:

1. **Near-term, narrow, high-value — rename M4.7 to the BIP-174 *Updater* role.**
   It completes the v0 role set (Creator/Updater are all that remain), is
   single-milestone-sized, vector-checkable, reuses the one PSBT/transaction
   model, and is the natural bridge to wallet workflows. This is the recommended
   *next implementation* milestone.

2. **Later, large, standards-defined — open a separate *BIP-370 / PSBT v2* track
   (e.g., M5.x).** This is the only interpretation where "merge" means more than
   `combine`. It must start with its own design review deciding whether KeyLab
   supports a second PSBT version and how the v2 model coexists with the v0 model
   *without* creating a parallel representation. Not an M4.7-sized step.

Either way, **M4.7 as "merge" is not well-defined**: the term conflates
already-delivered v0 combine with not-yet-scoped v2 work, and the genuinely
available v0 work (Updater) is mis-labeled.

---

## 7. Estimated implementation scope

- **(A) v0 "merge":** ~0 (would duplicate `combine`). Not recommended.
- **(C) BIP-174 Updater (recommended next):** **small–medium, one milestone.**
  New `keylab/psbt/updater.py` (`update_input`/`update_output`/`update` adding
  UTXO, redeem/witness script, BIP-32 derivation, sighash-type records with
  BIP-174 validity rules), reusing the existing model and validator; official
  BIP-174 Updater vectors as the oracle; the usual gates (tests, Hypothesis,
  negative, benchmark, SECURITY/feature_audit, docs). Comparable in size to the
  Signer/Finalizer/Extractor milestones just delivered.
- **(B) BIP-370 / PSBT v2:** **large, multi-milestone track.** v2 field
  constants and model, v2 (de)serialization, v2 validation, v2 locktime/tx
  assembly, conversion/compat with v0, and v2-aware signer/finalizer/extractor;
  plus a prerequisite design review on single-vs-dual PSBT model. Should be
  planned as M5.x, not folded into "M4.7."

---

## Conclusion

The research shows "PSBT merge" is not a distinct, well-defined BIP-174 v0
capability: v0 merge == the Combiner, already delivered in M4.6. The only
functionality that extends merge semantics is BIP-370 (PSBT v2), which is a
large separate track; the only narrowly-scoped v0 work remaining is the Updater,
which should not be called "merge." A naming/scope decision is required before
any implementation.

**M4.7 NOT YET WELL-DEFINED**

Reasoning: (1) BIP-174 defines no "Merger" role — v0 merging is the Combiner,
shipped in M4.6, so option (A) would duplicate existing code (forbidden by the
directive); (2) the only interpretation where "merge" means more than `combine`
is BIP-370 / PSBT v2, which is a multi-milestone standards track requiring its
own design review (single-vs-dual PSBT model) rather than a single M4.7 step;
(3) the genuinely available, narrowly-scoped v0 work is the **Updater** role,
which is well-defined and recommended as the next milestone **but must be renamed
from "merge."** Until that A/B/C naming-and-scope decision is made, M4.7 as
"merge" cannot be implemented correctly.
