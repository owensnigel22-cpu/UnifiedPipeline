# M4.6 — PSBT Combine (BIP-174 Combiner role) — Implementation Plan

**Status:** PLANNING ONLY. No code is implemented in this plan; it defines scope
and approach for a future M4.6 PR and claims no runtime capability.

**Builds on:** M4.2 `keylab.psbt` (parse/validate/serialize, the `Psbt`/`PsbtMap`/
`KeyPair` model), M4.3 `keylab.psbt.signer`, M4.4 `keylab.psbt.finalizer`, M4.5
`keylab.psbt.extractor` (merged in PR #22, `dfa5a6f`), and
`keylab.encoding.transaction` (the single transaction model).

---

## 1. Scope

M4.6 implements **only** the BIP-174 **Combiner** role: merge two or more PSBTs
that describe the **same unsigned transaction** into one PSBT that carries the
union of their key-value pairs. The classic use is collecting partial signatures
produced by independent signers (M4.3) for later finalization (M4.4) and
extraction (M4.5).

### In scope
- A `keylab.psbt.combiner` submodule in the existing `keylab.psbt` namespace
  (no second PSBT model, no second transaction model).
- `combine(psbts) -> Psbt`: take an iterable of ≥1 structurally valid PSBTs with
  identical unsigned transactions and identical input/output counts, and return
  a new PSBT whose global map, each input map, and each output map hold the union
  of the corresponding maps' key-value pairs.
- Deterministic, well-defined merge semantics (see §2), unknown-key preservation,
  and rejection of incompatible PSBTs.

### Explicitly OUT of scope
- **PSBT merge** in the looser BIP-370/"different transactions" sense — M4.6 is
  strictly the BIP-174 v0 Combiner (same unsigned tx only).
- **Signing, finalizing, extracting, broadcasting** — the combiner performs no
  cryptography and builds no scripts; it only unions records.
- **Wallet workflows, descriptor wallets, multisig coordination, UI, research
  tooling.**
- **Conflict *resolution* by cryptographic judgement** — the combiner does not
  decide which of two differing values for the same key is "better"; it applies
  the deterministic BIP-174 rule (§2) and rejects genuinely incompatible inputs.

---

## 2. BIP-174 Combiner role requirements

Per BIP-174, a Combiner:

1. **Requires identical unsigned transactions.** Every input PSBT must carry the
   same global `PSBT_GLOBAL_UNSIGNED_TX` (byte-for-byte); otherwise the combine
   is rejected. This also fixes the input/output map counts, which must match.
2. **Unions key-value pairs per map.** For the global map and each input/output
   map, the result contains every `(key)` present in any input PSBT.
3. **Same key, same value → keep one.** When multiple PSBTs carry the same full
   key with the **same value**, the result keeps a single copy (deduplication).
4. **Same key, different value → BIP-174 "first value" rule.** When the same full
   key appears with **different** values, the Combiner "should" keep the first
   value seen (stable, input-order precedence). M4.6 implements this
   deterministic rule and documents it. (For finalized fields `0x07`/`0x08`, two
   well-formed finalizations of the same input are expected to be identical; a
   divergence is surfaced via an optional strict mode — see §4.)
5. **Preserves unknown and proprietary keys** by the same union rule — forward
   compatibility is retained.
6. **Is order-robust and idempotent:** `combine([a, b])` and `combine([b, a])`
   differ only where rule 4 applies (first-value precedence); `combine([a, a]) ==
   a` (up to record ordering, which the serializer/validator already tolerate);
   `combine([a]) == a`.

The combiner does **not** sign, finalize, extract, or validate signatures; it
only merges records and leaves interpretation to the signer/finalizer.

---

## 3. Interaction with signer / finalizer / extractor

- **Signer (M4.3):** the primary producer of inputs to combine. Two signers each
  add a `PSBT_IN_PARTIAL_SIG` (`0x02`) keyed by their own pubkey; `combine`
  unions them so a single PSBT holds both partial signatures. (For the two
  supported single-key types this is informational — one signature per input
  suffices — but the union mechanics and dedup are exercised and tested.)
- **Finalizer (M4.4):** runs **after** combine. The combined PSBT is the input to
  `finalize`; the combiner never finalizes. If inputs are already finalized,
  union still applies (identical `0x07`/`0x08` dedup; divergence → strict-mode
  error).
- **Extractor (M4.5):** unchanged; it consumes a finalized PSBT, which may have
  been produced from a combined one. No extractor changes in M4.6.
- **Model reuse:** operates purely on `Psbt`/`PsbtMap`/`KeyPair`; the unsigned tx
  is compared via `Psbt.unsigned_tx_bytes` and parsed with the existing
  `parse_transaction` only to confirm counts. No new transaction logic.

---

## 4. Validation strategy

**Pre-combine (raise `PsbtCombineError`):**
1. At least one PSBT supplied; each passes M4.2 `validate()`.
2. All share a byte-identical `PSBT_GLOBAL_UNSIGNED_TX`; matching input/output
   map counts.
3. (Strict mode, default on) no two PSBTs present the same full key with
   conflicting values in a field where conflict is semantically illegal
   (`PSBT_GLOBAL_UNSIGNED_TX`, and finalized `0x07`/`0x08`). A conflict there
   raises; elsewhere the first-value rule (§2.4) applies silently. A
   `strict=False` mode downgrades all conflicts to the first-value rule for
   maximal BIP-174 leniency.

**Post-combine (must hold):**
1. The result passes M4.2 `validate()`.
2. The result's unsigned tx equals the common input unsigned tx.
3. Every key present in any input is present exactly once in the result; every
   kept value equals the value chosen by the §2 rules.
4. `serialize(combine(...))` round-trips (`parse` of it re-validates and equals).

**Oracle priority (unchanged doctrine): the vectors win.** Official BIP-174
Combiner vectors are primary; the existing parser/validator and the
signer/finalizer outputs are secondary.

---

## 5. Vector requirements

- **Primary:** the official BIP-174 **Combiner** test vectors from
  `bip-0174.mediawiki` (the "Combiner" worked example: two input PSBTs and the
  expected combined PSBT). Added as a new fixture
  `tests/vectors/bip174_combiner_vectors.json`, pinned in `SOURCES.json` with the
  same provenance discipline (40-char commit + CRLF→LF sha256, `mode: extracted`)
  used for the existing BIP-174 fixture; `scripts/vectors.py verify` stays green.
- For each vector: `serialize(combine([psbt_a, psbt_b]))` equals the expected
  combined PSBT **byte-for-byte** (modulo the record ordering BIP-174 permits — if
  the official expected bytes assume a specific order, the test asserts byte
  equality; otherwise it asserts key/value-set equality via parse).
- **Cross-role vector:** using the existing `bip143_signing_vectors.json`, build
  two PSBTs for the same unsigned tx (one empty, one signed), combine them, and
  assert the signed partial sig survives and the result finalizes+extracts to the
  same BIP-143 final tx as the un-combined path.

---

## 6. Security considerations

- The combiner performs **no cryptography**: it does not sign, verify, finalize,
  or build scripts. It cannot forge or alter a signature; it only unions existing
  records.
- **No network, no broadcast, no I/O.** Inputs never mutated; output is a new
  `Psbt`.
- **Untrusted-input safety:** combining PSBTs from independent/untrusted parties
  is the combiner's job, so it must not crash or silently corrupt on adversarial
  records — unknown keys are preserved verbatim, conflicting critical fields are
  rejected (strict mode), and no value is interpreted. It copies no secret
  material (PSBTs hold no private keys).
- SECURITY.md and `feature_audit` updated: `keylab.psbt` can now **combine** PSBTs
  that share an unsigned transaction, **for study/test-vector verification only**;
  still no broadcast, no merge of differing transactions, no wallet, no
  P2WSH/Taproot/multisig semantics.

---

## 7. Test plan

New `tests/test_psbt_combiner.py`:

**Positive / correctness**
- Official BIP-174 Combiner vector(s): byte-exact (or key/value-set) match.
- Union of two distinct partial sigs on one input; dedup of identical records;
  first-value precedence on a benign differing non-critical key.
- Cross-role: empty+signed → combine → finalize → extract equals the BIP-143
  final tx; order independence (`combine([a,b])` vs `combine([b,a])` agree except
  where §2.4 applies).
- `combine([a]) == a`; `combine([a,a])` equals `a` (key/value-set).

**Negative (raise `PsbtCombineError`)**
- Differing unsigned transactions; mismatched input/output counts; empty input
  list; a structurally invalid member; conflicting critical field in strict mode.

**Property-based (Hypothesis)**
- For random valid single-input PSBTs over the same unsigned tx with disjoint
  unknown-key sets, `combine` yields the exact union and round-trips; combining is
  commutative on disjoint keys and idempotent on repeats.

**Regression + benchmark gate**
- Pin the official Combiner vector as a regression; a correctness-gated benchmark
  test.

**Quality gates:** all 11 CI green; `validate_all()` = 0; coverage floor held or
raised; mypy baseline unchanged or improved; fixtures verified;
`gen_api_docs --check` clean.

---

## 8. Benchmark plan

`keylab.benchmarks.benchmark_psbt_combine` — correctness-gated: combine the
official Combiner vector (and a constructed two-signer case), assert the combined
output matches the expected result, then time `combine`. Reports
`cases`, `outputs_match_vectors`, `us_per_combine`. No optimization work —
measurement only, same pattern as `benchmark_psbt_sign/finalize/extract`.

---

## 9. API proposal (for review, not yet built)

```
keylab.psbt.combine(psbts: Iterable[Psbt], *, strict: bool = True) -> Psbt
keylab.psbt.PsbtCombineError   # subclass of PsbtError
```

Re-exported from `keylab.psbt` alongside the existing
parse/validate/serialize/sign/finalize/extract surface. Exact names/signatures
are subject to review at implementation time. No change to
`keylab.encoding.transaction` is anticipated (the combiner works on the PSBT
model only).

---

## 10. Exit criteria

M4.6 is complete when: the official BIP-174 Combiner vector(s) combine to the
expected result; the union/dedup/first-value and order-independence rules hold
under test; the cross-role combine→finalize→extract path reproduces the BIP-143
final transaction; negative/property/regression suites pass; all 11 CI jobs are
green on the M4.6 PR; SECURITY.md and `feature_audit` reflect "combines PSBTs
sharing an unsigned transaction; no cryptography, no broadcast, no merge of
differing transactions"; coverage floor held or raised; mypy baseline unchanged
or improved; fixtures verified; API docs regenerated; and no broadcast, merge,
wallet, research, or P2WSH/Taproot/multisig code was introduced.

---

**DO NOT IMPLEMENT (this milestone, per instruction):** this document is the plan
only. Implementation of M4.6 awaits explicit approval to begin.

READY FOR M4.6 PLANNING REVIEW
