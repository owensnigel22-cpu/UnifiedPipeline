# M4.7 — BIP-174 Updater role — Implementation Plan

**Status:** PLANNING ONLY. No code is implemented in this plan; it defines scope
and approach for a future M4.7 PR and claims no runtime capability.

**Renamed from "PSBT merge"** per `M4_7_PSBT_MERGE_DESIGN_REVIEW.md` (approved):
v0 merge is already the Combiner (M4.6); the real, narrowly-scoped remaining v0
role is the **Updater**. BIP-370/PSBT v2 is deferred to a separate M5.x track.

**Builds on:** M4.2 `keylab.psbt` (parse/validate/serialize, the `Psbt` /
`PsbtMap` / `KeyPair` model), M4.3 signer, M4.4 finalizer, M4.5 extractor, M4.6
combiner (merged at `main = 1073caa`), and `keylab.encoding.transaction` (the
single transaction model). Supported script types stay **P2WPKH and
P2SH-P2WPKH only**.

---

## 1. Scope

M4.7 implements the BIP-174 **Updater** role: given a PSBT (typically just an
unsigned transaction with empty input/output maps) and per-input/per-output
metadata, add the key-value records a Signer needs — UTXO information, the P2SH
redeem script, BIP-32 derivation paths, and the sighash type — producing a PSBT
ready for the existing M4.3 signer. The Updater adds *metadata only*; it performs
no cryptography.

### In scope
- A `keylab.psbt.updater` submodule in the existing `keylab.psbt` namespace (no
  second PSBT model, no second transaction model).
- Add, per **input**: `PSBT_IN_WITNESS_UTXO` (`0x01`), optionally
  `PSBT_IN_NON_WITNESS_UTXO` (`0x00`), `PSBT_IN_REDEEM_SCRIPT` (`0x04`, for
  P2SH-P2WPKH), `PSBT_IN_BIP32_DERIVATION` (`0x06`), `PSBT_IN_SIGHASH_TYPE`
  (`0x03`).
- Add, per **output**: `PSBT_OUT_REDEEM_SCRIPT` (`0x00`),
  `PSBT_OUT_BIP32_DERIVATION` (`0x02`).
- Preserve existing records and unknown keys; never mutate the input PSBT
  (return a new `Psbt`); re-validate the result with the M4.2 validator.

### Explicitly OUT of scope
- **Signing, finalizing, extracting, combining, broadcasting** — other roles,
  already delivered or deferred.
- **`PSBT_IN_WITNESS_SCRIPT` (`0x05`) / `PSBT_OUT_WITNESS_SCRIPT` (`0x01`)** and
  any **P2WSH / Taproot / multisig** metadata — out of the supported script set.
- **Adding partial signatures or finalized fields** (`0x02`, `0x07`, `0x08`) —
  those belong to the signer/finalizer; the Updater must refuse to set them.
- **Wallet workflows, descriptor wallets, key derivation** — the Updater takes
  already-derived data from the caller; BIP-32 derivation itself stays in
  `keylab.hd`.

---

## 2. Official BIP-174 Updater requirements

Per BIP-174, an Updater:

1. **Adds only metadata needed for signing**, never signatures. For each input it
   knows about, it may add the UTXO being spent, the redeem/witness script, and
   BIP-32 derivation paths; for each output, the redeem/witness script and
   derivations.
2. **UTXO records:** for a witness input, `PSBT_IN_WITNESS_UTXO` carries the
   spent `CTxOut` (8-byte amount + length-prefixed scriptPubKey); for a
   non-witness input, `PSBT_IN_NON_WITNESS_UTXO` carries the **full previous
   transaction** whose txid must match the input's prevout hash.
3. **Must not change the unsigned transaction** and must not add records to an
   input/output index that does not exist.
4. **Singleton vs keyed fields:** UTXO, redeem script, witness script, and
   sighash type are singletons (no key data); BIP-32 derivation is keyed by a
   33/65-byte public key with value = 4-byte master fingerprint followed by the
   32-bit little-endian derivation path.
5. **Does not duplicate or clobber:** adding a record that already exists with
   the same value is a no-op; a conflicting value is rejected (see §4).
6. **Preserves unknown/proprietary keys.**

The Updater does **not** sign, finalize, extract, or combine, and does not derive
keys.

---

## 3. Supported metadata fields

Input map (within the P2WPKH / P2SH-P2WPKH scope):

| Field | Type | Form | Notes |
|---|---|---|---|
| Witness UTXO | `0x01` | amount(8 LE) + `ser_string(scriptPubKey)` | from a `TxOut` or `(amount, scriptPubKey)` |
| Non-witness UTXO | `0x00` | full previous transaction bytes | optional; txid must match the prevout |
| Redeem script | `0x04` | raw script | P2SH-P2WPKH only (`0x0014{20}`); must hash to the P2SH scriptPubKey |
| BIP-32 derivation | `0x06` | key=`0x06`+pubkey(33/65); value=fp(4)+path(4·n LE) | pubkey-keyed |
| Sighash type | `0x03` | 4-byte LE | one of the supported BIP-143 flags |

Output map:

| Field | Type | Form |
|---|---|---|
| Redeem script | `0x00` | raw script |
| BIP-32 derivation | `0x02` | key=`0x02`+pubkey; value=fp(4)+path(4·n LE) |

Explicitly **not** added: witness script (`0x05`/`0x01`), partial sig (`0x02`
input), finalized fields (`0x07`/`0x08`).

---

## 4. Validation strategy

**Pre-update (raise `PsbtUpdateError`):**
1. `validate(psbt)` (M4.2 structural rules) passes.
2. The target input/output index is in range for the unsigned transaction.
3. A requested witness-UTXO value is a well-formed `CTxOut`; a non-witness UTXO
   parses and its double-SHA256 equals the input's prevout hash; a redeem script
   for a P2SH input hashes to that input's scriptPubKey; a derivation's keydata
   is a 33/65-byte pubkey and its value is 4 + 4·n bytes; a sighash type is a
   supported flag.
4. Refuse to set signer/finalizer fields (`0x02`, `0x07`, `0x08`) — not the
   Updater's role.
5. Adding a record already present with the **same** value is a no-op; a
   **different** value is rejected (no silent clobber).

**Post-update (must hold):**
1. The result passes M4.2 `validate()`.
2. The unsigned transaction is unchanged; only the targeted maps gained records.
3. `serialize(update(...))` round-trips (parse re-validates and equals).

**Oracle priority (unchanged doctrine): the vectors win.** Official BIP-174
Updater material is primary where it is in scope; the existing
parser/validator and the end-to-end signer→finalizer→extractor path are the
secondary oracle.

---

## 5. Vector requirements

- **Primary (in-scope end-to-end):** reuse `tests/vectors/bip143_signing_vectors.json`.
  Start from a bare PSBT (unsigned tx + empty maps), run the Updater to add
  witness UTXO (+ redeem script for P2SH-P2WPKH), then **sign → finalize →
  extract** and assert the result equals the BIP-143 worked-example final
  transaction **byte-for-byte**. This proves the Updater produces exactly the
  metadata the signer needs, against an official oracle.
- **BIP-174 Updater worked example:** the official Updater step mutates a PSBT by
  adding records; where its record *shapes* (witness UTXO, redeem script,
  derivation, sighash) fall within the supported field set, assert the Updater
  produces the same record bytes. (The spec's example uses multisig/P2WSH scripts
  that are out of KeyLab's script scope, so the end-to-end multisig result is not
  reproduced — only the in-scope record-construction shapes.) If a dedicated
  in-scope fixture is warranted, add `tests/vectors/bip174_updater_vectors.json`
  with the same pinned-provenance discipline (`SOURCES.json`, 40-char commit,
  CRLF→LF sha256, `mode: extracted`) and keep `scripts/vectors.py verify` green.
- **Derivation cross-check:** derive a key via `keylab.hd`
  (`mnemonic → derive_private_path`), add its `PSBT_IN_BIP32_DERIVATION` with the
  master fingerprint (`keylab.hd.fingerprint`), and confirm the signer can match
  and sign that input.

---

## 6. Security considerations

- The Updater performs **no cryptography**: it adds metadata only, derives no
  keys, and signs nothing. It cannot create or alter a signature.
- **No network, no I/O**; inputs never mutated; output is a new `Psbt`.
- **Untrusted-input safety:** it validates every record it adds (well-formed
  UTXO, matching prevout/redeem hashes, correct key/value shapes) and refuses to
  set signer/finalizer fields, so a malformed or over-reaching update is rejected
  rather than silently accepted.
- It copies no secret material — a PSBT holds no private keys, and BIP-32
  derivation records carry only public keys, fingerprints, and paths.
- SECURITY.md and `feature_audit` updated: `keylab.psbt` can now **update**
  (add signing metadata to) a PSBT for P2WPKH / P2SH-P2WPKH, **for study /
  test-vector verification only**; still no key derivation inside the updater, no
  broadcast, no P2WSH/Taproot/multisig, not production wallet software.

---

## 7. Test plan

New `tests/test_psbt_updater.py`:

**Positive / correctness**
- End-to-end: bare PSBT → update → sign → finalize → extract equals the BIP-143
  final tx (both supported types).
- Add witness UTXO from a `TxOut` and from `(amount, scriptPubKey)`; add redeem
  script for P2SH-P2WPKH; add a BIP-32 derivation and sighash type; output
  redeem script + derivation.
- Idempotent add (same value → no-op); round-trip serialize/update/serialize.
- HD cross-check: derivation added for a `keylab.hd`-derived key is matched by
  the signer.

**Negative (raise `PsbtUpdateError`)**
- Out-of-range index; malformed witness UTXO; non-witness UTXO whose txid ≠
  prevout; redeem script that does not hash to the P2SH scriptPubKey; malformed
  derivation value/length; unsupported sighash flag; attempt to set `0x02` /
  `0x07` / `0x08`; conflicting value for an existing record.

**Property-based (Hypothesis)**
- For random valid single-input PSBTs, adding then re-adding the same metadata is
  idempotent; the update only grows the targeted map and round-trips; the
  unsigned tx is never altered.

**Regression + benchmark gate**
- Pin one in-scope end-to-end result; a correctness-gated benchmark test.

**Quality gates:** all 11 CI green; `validate_all()` = 0; coverage floor held or
raised; mypy baseline unchanged or improved; fixtures verified;
`gen_api_docs --check` clean.

---

## 8. Benchmark plan

`keylab.benchmarks.benchmark_psbt_update` — correctness-gated: update the
bare BIP-143 single-input and multi-input cases, then sign→finalize→extract and
assert the official final tx; time the `update` step. Reports `cases`,
`single_input_cases`, `multi_input_cases`, `outputs_match_vectors`,
`us_per_update`. No optimization work — measurement only, same pattern as the
sign/finalize/extract/combine benchmarks.

---

## 9. API proposal (for review, not yet built)

```
keylab.psbt.update_input(
    psbt, index, *,
    witness_utxo=None,          # TxOut | (amount:int, script_pubkey:bytes)
    non_witness_utxo=None,      # bytes (full previous tx)
    redeem_script=None,         # bytes (P2SH-P2WPKH)
    bip32_derivations=None,     # {pubkey: (fingerprint, [path ints])}
    sighash_type=None,          # int
) -> Psbt

keylab.psbt.update_output(
    psbt, index, *, redeem_script=None, bip32_derivations=None
) -> Psbt

keylab.psbt.PsbtUpdateError   # subclass of PsbtError
```

Re-exported from `keylab.psbt` alongside the existing
parse/validate/serialize/sign/finalize/extract/combine surface. No change to
`keylab.encoding.transaction` is anticipated (helpers reuse `compact_size` /
`ser_string` / `TxOut`). Exact names/signatures are subject to review at
implementation time.

---

## 10. Exit criteria

M4.7 (Updater) is complete when: a bare PSBT updated by the Updater then
signed → finalized → extracted reproduces the BIP-143 worked-example final
transactions **byte-for-byte** for both supported types; in-scope Updater record
shapes match the official BIP-174 example; the negative/property/regression
suites pass; all 11 CI jobs are green on the M4.7 PR; SECURITY.md and
`feature_audit` reflect "adds signing metadata (Updater) for P2WPKH /
P2SH-P2WPKH, no cryptography, no key derivation, no broadcast"; coverage floor
held or raised; mypy baseline unchanged or improved; fixtures verified; API docs
regenerated; and no signing/finalizing/extracting/combining, no
P2WSH/Taproot/multisig, and no second model were introduced.

---

**DO NOT IMPLEMENT (this milestone, per instruction):** this document is the
plan only. Implementation of M4.7 (Updater) awaits explicit approval to begin.

READY FOR M4.7 UPDATER REVIEW
