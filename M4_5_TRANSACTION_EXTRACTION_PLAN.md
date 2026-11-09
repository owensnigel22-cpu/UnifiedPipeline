# M4.5 — Transaction Extraction (BIP-174 Extractor role) — Implementation Plan

**Status:** PLANNING ONLY. No code is implemented in this milestone's plan; it
defines scope and approach for a future M4.5 PR and claims no runtime capability.

**Builds on:** M4.2 `keylab.psbt` (parse/validate/serialize), M4.3
`keylab.psbt.signer`, M4.4 `keylab.psbt.finalizer` (merged in PR #21,
`7fc23f8`), and `keylab.encoding.transaction` (the single transaction model:
`Transaction`, `TxIn`, `TxOut`, `parse_transaction`, `compact_size`,
`ser_string`). Supported input types stay **P2WPKH and P2SH-P2WPKH only**.

---

## 1. Scope

M4.5 implements **only** the BIP-174 **Extractor** role: given a PSBT whose
inputs are all finalized (M4.4), produce the final **network-serialized
(BIP-144) transaction** ready to be handed to a broadcaster elsewhere.

### In scope
- A `keylab.psbt.extractor` submodule in the existing `keylab.psbt` namespace
  (no second PSBT model).
- Assemble the final `Transaction` by taking the PSBT's unsigned transaction and,
  per input, injecting the finalized `scriptSig` (`PSBT_IN_FINAL_SCRIPTSIG`,
  `0x07`) into `TxIn.script_sig` and the finalized `scriptWitness`
  (`PSBT_IN_FINAL_SCRIPTWITNESS`, `0x08`) into `TxIn.witness`.
- A **transaction serializer** added to `keylab.encoding.transaction` (the single
  transaction model — **not** a second model): `serialize_transaction(tx)` that
  emits legacy serialization when no input has witness data and BIP-144 segwit
  serialization (marker `0x00`, flag `0x01`, per-input witness stacks) when any
  input does. This is the inverse of the existing `parse_transaction`.
- `extract(psbt) -> bytes` returning the serialized transaction; optionally
  `extract_transaction(psbt) -> Transaction` returning the assembled model.

### Explicitly OUT of scope
- **Transaction broadcast / any network I/O** (the extractor returns bytes only).
- **Wallet workflows, PSBT combine/merge, multisig coordination, descriptor
  wallets, research tooling.**
- **Finalization** (done in M4.4) and **signing** (M4.3) — the extractor consumes
  an already-finalized PSBT and performs no cryptography.
- **P2WSH / Taproot / multisig** extraction (only the two finalized types).
- Fee, weight/vsize, or txid/wtxid computation beyond what a test cross-check
  needs (no mempool-policy or consensus checks).

---

## 2. Relationship to finalized PSBTs

- The extractor's precondition is `keylab.psbt.is_finalized(psbt) is True`: every
  input carries `0x07` and/or `0x08`. If any input is not finalized, the
  extractor raises (it does not attempt to finalize — that is M4.4's job).
- For each input it reads **only** the finalized fields and the unsigned tx; it
  ignores (and does not require) UTXO/redeem/partial-sig fields, which M4.4 may
  already have removed. Unknown/proprietary fields are irrelevant to extraction
  and are not copied into the transaction.
- Native **P2WPKH** inputs have no `0x07` (empty scriptSig) and a `0x08` witness;
  **P2SH-P2WPKH** inputs have both a `0x07` scriptSig (the redeemScript push) and
  a `0x08` witness. The extractor maps each present field to the corresponding
  `TxIn` component and leaves the scriptSig empty when `0x07` is absent.
- The resulting transaction's non-witness structure (version, inputs' outpoints
  and sequences, outputs, locktime) is identical to the PSBT's unsigned tx; only
  scriptSigs and witnesses are filled in.

---

## 3. Extraction requirements

1. **Finalized-only:** raise `PsbtExtractError` if `is_finalized` is false.
2. **Field mapping:** `TxIn.script_sig = final_scriptsig or b""`;
   `TxIn.witness = parsed stack from final_scriptwitness`. The `0x08` value is a
   count-prefixed witness stack (`compact_size(n)` then `ser_string` per item) —
   decode it into a `tuple[bytes, ...]` with the existing `_Reader`.
3. **Serialization form:** segwit (BIP-144) iff any input has a non-empty
   witness; otherwise legacy. For the two supported types at least one input
   always has a witness, so output is segwit-serialized.
4. **Byte-exactness:** for the BIP-143 worked examples, the extracted transaction
   equals the BIP-143 **final signed transaction** hex byte-for-byte.
5. **Determinism & purity:** no RNG, no I/O, no mutation of the input PSBT.
6. **No cryptography:** the extractor neither signs nor verifies; it only
   rearranges already-present bytes (a correctness cross-check in tests may
   re-verify, but the extractor path itself does not).

---

## 4. Validation strategy

**Pre-extraction (raise on failure):**
- `validate(psbt)` (M4.2 structural rules) passes.
- `is_finalized(psbt)` is true (all inputs finalized).
- Each `0x08` witness value decodes as a well-formed witness stack; each `0x07`
  value is a byte string usable as a scriptSig.

**Post-extraction (must hold before returning):**
- `parse_transaction(extract(psbt))` round-trips to an equal `Transaction`
  (serializer/parser are mutual inverses).
- The extracted transaction's version/inputs(outpoints,sequence)/outputs/locktime
  match the PSBT's unsigned transaction exactly; only scriptSig/witness differ.

**Oracle priority (unchanged doctrine): the vectors win.** The BIP-143 final
transactions are the primary oracle; the existing `parse_transaction` and the
M4.4 finalizer outputs are the secondary oracle.

---

## 5. Vector requirements

- **Primary:** the BIP-143 worked-example **final signed transactions** for
  native P2WPKH and P2SH-P2WPKH. These are already pinned in
  `tests/vectors/bip143_signing_vectors.json`
  (`unsigned_tx` + the finalized `final_scriptsig`/`final_scriptwitness`); M4.5
  adds a `final_tx` field (the full signed tx hex) to each case, extracted from
  the same pinned BIP-143 commit `24e96e8…`, with the fixture's `sha256` updated
  in `SOURCES.json` in the same change. `scripts/vectors.py verify` must stay
  green.
- For each case: sign (M4.3) → finalize (M4.4) → extract (M4.5), and assert the
  extracted bytes equal `final_tx` **byte-for-byte**.
- **Round-trip vectors:** `parse_transaction(serialize_transaction(tx)) == tx`
  for the BIP-143 transactions and the existing transaction fixtures (covers the
  new serializer independently of PSBT).

---

## 6. Security considerations

- The extractor **performs no cryptography and creates nothing**: it only moves
  already-finalized bytes into transaction fields. It cannot forge or alter a
  signature.
- **No network, no broadcast, no I/O** — it returns bytes; broadcasting is out of
  scope and remains unavailable.
- It never mutates the input PSBT and copies no secret material (a finalized PSBT
  holds no private keys; the extractor also drops partial sigs by construction).
- SECURITY.md and `feature_audit` updated: `keylab.psbt` can now produce a final
  serialized transaction from a finalized PSBT **for study/test-vector
  verification only**; it still does **not** broadcast, combine/merge, or handle
  P2WSH/Taproot/multisig, and is not production wallet software. The new
  `transaction.serialize_transaction` is a serializer, not a consensus validator.

---

## 7. Test plan

New `tests/test_psbt_extractor.py` plus transaction-serializer tests in the
existing transaction test module:

**Positive / correctness**
- BIP-143 end-to-end: sign → finalize → extract equals `final_tx` byte-for-byte
  (both supported types).
- `serialize_transaction` round-trips with `parse_transaction` for the BIP-143
  txs, a legacy (no-witness) tx, and existing transaction fixtures.
- Extracted tx preserves version/outpoints/sequence/outputs/locktime of the
  unsigned tx.

**Negative (raise `PsbtExtractError`)**
- Not all inputs finalized; a `0x08` witness value that is malformed/truncated;
  an input with neither `0x07` nor `0x08`; (defensively) a PSBT whose unsigned tx
  is missing.

**Property-based (Hypothesis)**
- For a signed+finalized P2WPKH PSBT over a random key, extraction round-trips
  through `parse_transaction` and preserves the unsigned-tx skeleton; the input
  PSBT is unchanged.

**Regression**
- Pin the two BIP-143 final-tx hashes as explicit byte-exact assertions.

**Benchmark gate**
- A correctness-gated benchmark test (as with sign/finalize).

---

## 8. Benchmark plan

`keylab.benchmarks.benchmark_psbt_extract` — correctness-gated: extract the
BIP-143 single-input (P2SH-P2WPKH) and multi-input (P2WPKH example) finalized
PSBTs, assert the output equals `final_tx`, then time extraction. Reports
`single_input_cases`/`multi_input_cases`, `outputs_match_vectors`,
`us_per_extract`. No optimization work — measurement only, same pattern as
`benchmark_psbt_sign` / `benchmark_psbt_finalize`.

---

## 9. API proposal (for review, not yet built)

```
keylab.psbt.extract(psbt) -> bytes                     # final network-serialized tx
keylab.psbt.extract_transaction(psbt) -> Transaction   # the assembled model (optional)
keylab.psbt.PsbtExtractError                            # subclass of PsbtError

keylab.encoding.transaction.serialize_transaction(tx: Transaction) -> bytes
    # legacy, or BIP-144 segwit when any input has witness data;
    # exact inverse of parse_transaction
```

Re-exported from `keylab.psbt` alongside the existing
parse/validate/serialize/sign/finalize surface. Exact names/signatures are
subject to review at implementation time.

---

## 10. Exit criteria

M4.5 is complete when: `serialize_transaction` is the exact inverse of
`parse_transaction` (legacy + segwit) under test; extracting the finalized
BIP-143 worked examples yields the official final transactions **byte-for-byte**;
the negative/property/regression suites pass; all 11 CI jobs are green on the
M4.5 PR; SECURITY.md and `feature_audit` reflect "extracts a final serialized
transaction from a finalized PSBT, does not broadcast"; coverage floor held or
raised; mypy baseline unchanged or improved; fixtures verified; API docs
regenerated; and no broadcast, combine/merge, wallet, research, or
P2WSH/Taproot/multisig code was introduced.

---

**DO NOT IMPLEMENT (this milestone, per instruction):** this document is the
plan only. Implementation of M4.5 awaits explicit approval to begin.

READY FOR M4.5 PLANNING REVIEW
