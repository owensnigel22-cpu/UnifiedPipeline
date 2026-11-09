# M4.3 — PSBT Signing (BIP-174 Signer role) — Implementation Plan

**Status:** PLANNING ONLY. No code in this milestone's plan is implemented yet.
This document defines the scope and approach for a future M4.3 implementation
PR; it does not add, change, or claim any runtime capability.

**Builds on:** M4.2 `keylab.psbt` (parse / validate / serialize, merged in PR
\#19, commit `721aa45`), `keylab.encoding.transaction` (BIP-143 sighashing),
`keylab.mnemonic` + `keylab.hd` (BIP-39 / BIP-32 key material), and
`keylab.ec.secp256k1` (ECDSA over secp256k1).

---

## 1. Scope

M4.3 implements **only the BIP-174 Signer role**: given a PSBT and signing key
material, compute ECDSA signatures for the inputs the signer can sign, and add
them to the PSBT as `PSBT_IN_PARTIAL_SIG` (`0x02`) records (and, where
applicable, `PSBT_IN_SIGHASH_TYPE` `0x03`). The result is a PSBT with partial
signatures attached; it re-serializes under the existing M4.2 serializer and
re-validates under the existing M4.2 validator.

### In scope

- A `keylab.psbt.signer` module (new submodule inside the existing
  `keylab.psbt` namespace — **no second PSBT model, no second transaction
  model**).
- Compute the Signer-role sighash for an input, using the UTXO information
  already carried in the PSBT input map (`PSBT_IN_WITNESS_UTXO` `0x01` or
  `PSBT_IN_NON_WITNESS_UTXO` `0x00`) and the relevant script
  (`PSBT_IN_REDEEM_SCRIPT` `0x04` / `PSBT_IN_WITNESS_SCRIPT` `0x05` when
  present).
- Produce deterministic ECDSA signatures (low-S, DER-encoded + 1-byte sighash
  flag appended, per Bitcoin convention) via
  `keylab.ec.secp256k1.ecdsa_sign_digest`.
- Insert `PSBT_IN_PARTIAL_SIG` records keyed by the 33-byte compressed public
  key, and `PSBT_IN_SIGHASH_TYPE` where a non-default sighash is used, without
  disturbing existing records or unknown keys.
- A pure, explicit "which inputs can this key sign" determination driven by the
  PSBT's own derivation data (`PSBT_IN_BIP32_DERIVATION` `0x06`) and/or a
  caller-supplied `{pubkey: private_scalar}` map.

### Explicitly OUT of scope for M4.3 (deferred / excluded)

- **PSBT finalization** (building `PSBT_IN_FINAL_SCRIPTSIG` `0x07` /
  `PSBT_IN_FINAL_SCRIPTWITNESS` `0x08`). Deferred to a later milestone.
- **Transaction extraction** (producing a network-serialized, fully signed
  transaction). Deferred.
- **Wallet workflows** — no key storage, no account discovery, no coin
  selection, no fee logic, no UTXO scanning, no PSBT Creator/Updater/Combiner
  convenience flows beyond what the Signer strictly needs.
- **Research tooling** — no nonce analysis, lattice, kangaroo, RNG diagnostics,
  or any `keylab.research.*` interaction.
- **Taproot / Schnorr PSBT signing** (BIP-371 key-path/script-path PSBT
  fields). M4.3 targets ECDSA (legacy + segwit v0) only; Taproot PSBT signing
  is a candidate for a distinct later milestone.

This boundary keeps M4.3 to one well-defined BIP-174 role with a single
cryptographic operation (ECDSA sign) and no transaction broadcast surface.

---

## 2. Signing responsibilities

The Signer, per BIP-174, must:

1. **Only sign what it can.** For each input, determine whether the signer
   holds a key that participates in that input's script, using the input's
   derivation records and/or the caller-provided key map. Inputs it cannot sign
   are left untouched.
2. **Use the correct UTXO and script.** For a witness input, the amount and
   `scriptPubKey`/`witnessScript` drive the BIP-143 sighash; for a legacy
   input, the full previous transaction (`PSBT_IN_NON_WITNESS_UTXO`) is required
   and its `txid` must match the outpoint referenced by the unsigned tx.
3. **Verify prevout linkage before signing.** The `non_witness_utxo`'s
   double-SHA256 must equal the input's `prevout.hash`; the `witness_utxo`'s
   `scriptPubKey` must be consistent with any supplied redeem/witness script.
   Mismatch ⇒ refuse to sign that input (raise, do not silently skip), because
   signing against an unverified amount is exactly the class of bug BIP-143 and
   PSBT were designed to prevent.
4. **Produce canonical signatures.** Low-S normalized (reuse
   `keylab.ec.secp256k1.is_high_s_signature` to assert/normalize), DER-encoded,
   with the 1-byte sighash type appended.
5. **Attach, never overwrite.** Add `PSBT_IN_PARTIAL_SIG` under the signer's
   pubkey; refuse to clobber an existing partial sig for the same pubkey
   (duplicate-key protection already enforced by the M4.2 parser/validator on
   re-serialization).
6. **Preserve the document.** The output PSBT differs from the input only by
   the added records; global map, other inputs/outputs, ordering of pre-existing
   records, and unknown keys are preserved. `serialize(sign(parse(x)))` changes
   only the signed inputs' maps.
7. **Be deterministic and side-effect-free.** No RNG for nonces (RFC 6979 via
   the existing deterministic `ecdsa_sign_digest`), no I/O, no mutation of the
   caller's input object (return a new/clone PSBT or document the mutation
   contract explicitly).

The Signer **does not**: decide sighash policy beyond what the caller or the
input's `PSBT_IN_SIGHASH_TYPE` dictates, finalize, extract, broadcast, or
manage keys.

---

## 3. Interaction with BIP-39 (`keylab.mnemonic` / `keylab.hd`)

The Signer consumes **private scalars**, not mnemonics directly — this keeps the
signing surface narrow and testable, and keeps seed/mnemonic handling in the
existing HD layer.

- The documented end-to-end path for tests and examples:
  `mnemonic_to_seed` → `master_key` → `derive_private_path` (or the
  `derive_bip44/49/84` helpers) → `ExtendedKey` private scalar + its compressed
  pubkey → passed to the Signer.
- M4.3 adds an **optional convenience adapter** (not a wallet): given an
  `ExtendedKey` master/account key and a PSBT whose inputs carry
  `PSBT_IN_BIP32_DERIVATION` records, derive exactly the child keys whose
  fingerprint+path match, and build the `{pubkey: scalar}` map. This is a pure
  function over already-parsed derivation records; it performs no discovery and
  no scanning.
- **No new seed/mnemonic code.** All BIP-39/32 derivation is delegated to the
  existing, already-tested `keylab.mnemonic` and `keylab.hd` public APIs. The
  Signer never sees a mnemonic string or a seed; the adapter takes an
  `ExtendedKey`.
- **Fingerprint matching** uses the existing `keylab.hd.fingerprint` /
  `key_identifier` helpers so the master-fingerprint comparison in
  `PSBT_IN_BIP32_DERIVATION` is consistent with the rest of the library.

---

## 4. Interaction with BIP-143 (`keylab.encoding.transaction`)

Sighash computation is **delegated entirely** to the existing BIP-143/legacy
machinery — M4.3 adds no new sighash implementation.

- **Segwit v0 inputs** (`PSBT_IN_WITNESS_UTXO`): compute the sighash with
  `transaction.bip143_sighash(tx, input_index, script_code, amount, hash_type)`,
  where `tx` is the `Transaction` already parsed from the PSBT's unsigned-tx
  global record (`Psbt.unsigned_tx_bytes` → `parse_transaction`), `amount` and
  `script_code` come from the input's witness UTXO / witness script.
- **Legacy inputs** (`PSBT_IN_NON_WITNESS_UTXO`): compute the legacy sighash
  (the double-SHA256 of the legacy serialization with the signed input's
  scriptSig set to the subscript and others emptied). If the existing
  `transaction` module does not yet expose a public legacy-sighash function,
  M4.3 adds one there (`legacy_sighash`), co-located with the BIP-143 code, and
  reuses the existing `compact_size` / `ser_string` / `Transaction`
  serialization — **not** a parallel serializer in `keylab.psbt`.
- **`script_code` derivation** follows BIP-143 §"script_code": P2WPKH expands to
  the implied `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`; P2WSH uses
  the `witnessScript`; P2SH-wrapped forms use the `redeemScript`. These
  transformations are the Signer's responsibility (small, pure helpers), but the
  hashing itself stays in `transaction`.
- **Sighash flags** reuse the existing `SIGHASH_ALL/NONE/SINGLE/ANYONECANPAY`
  constants from `transaction`; the PSBT `PSBT_IN_SIGHASH_TYPE` value, when
  present, must be honored and must equal the flag used.
- The `Transaction`/`TxIn`/`TxOut` dataclasses from `transaction` are the single
  transaction model throughout — the PSBT layer never defines its own.

---

## 5. Validation strategy

Two layers, consistent with M4.2's "parse / validate / serialize" separation.

**Pre-sign validation (refuse to sign on any failure):**

1. Run the existing M4.2 `validate()` first — a signer only signs a
   structurally valid PSBT.
2. Unsigned tx present, non-witness-serialized, and still unsigned (empty
   scriptSigs, no witness) — already guaranteed by M4.2 `validate`; re-assert.
3. For each input to be signed: required UTXO record present; `non_witness_utxo`
   hash matches the outpoint; `witness_utxo` amount is a non-negative integer in
   range; redeem/witness script hashes match the `scriptPubKey` they claim to
   satisfy.
4. The signing key actually corresponds to a pubkey required by the input's
   script (reject "signing with an unrelated key").
5. Requested/record sighash type is one of the supported flags.

**Post-sign validation (must hold before returning):**

1. The produced signature **verifies** against the computed sighash and the
   signer's public key via `ecdsa_verify_digest` — a signer never emits a
   signature it has not itself checked (this is the primary correctness oracle,
   independent of any vector).
2. Signature is low-S and DER-canonical.
3. The output PSBT still passes M4.2 `validate()` and round-trips:
   `serialize(signed)` parses back to an equal structure.
4. No record other than the intended `PSBT_IN_PARTIAL_SIG` /
   `PSBT_IN_SIGHASH_TYPE` additions changed (diff is additive and confined to
   the signed inputs).

**Oracle priority (unchanged doctrine): the vectors win.** Official BIP-174
signer vectors are the primary oracle; `ecdsa_verify_digest` self-check and the
existing BIP-143 sighash tests are the secondary oracle; the vectors override
any internal assumption on conflict.

---

## 6. Vector requirements

- **Primary:** the official BIP-174 "Signer" worked examples from
  `bip-0174.mediawiki` (the signing test vectors deliberately excluded from
  M4.2's scope, which covered only parser/validator vectors). Each is pinned in
  `tests/vectors/SOURCES.json` with the same provenance discipline used in M4.2
  (40-char commit pin + CRLF→LF-normalized sha256, `mode: extracted`), as a new
  fixture file `tests/vectors/bip174_signer_vectors.json`.
- For each signer vector: parse the input PSBT, apply the documented key(s),
  and assert the **byte-exact** output PSBT equals the vector's expected
  post-signing PSBT.
- **Cross-oracle BIP-143 vectors:** reuse the existing BIP-143 sighash test
  vectors already in the repo to confirm the sighash the signer feeds into
  ECDSA matches the independently-tested `bip143_sighash` output for the same
  tx/input/amount/script.
- **Known-answer ECDSA:** deterministic (RFC 6979) signatures for fixed
  scalar+digest pairs, cross-checked against the existing
  `keylab.ec.secp256k1` ECDSA tests.
- If an official signer vector depends on finalization/extraction to express its
  expected output, only the **partial-signature** state is asserted (M4.3 stops
  at Signer); the finalized form is explicitly out of scope and not claimed.

---

## 7. Security requirements

- **Documentation gates (SECURITY.md + `feature_audit`)** updated to state that
  `keylab.psbt` now computes and attaches **partial ECDSA signatures for study
  and test-vector verification**, and still **does not** finalize, extract,
  combine, broadcast, manage keys, or constitute production wallet software.
  The existing "Not a wallet" positioning is tightened, not relaxed.
- **Deterministic nonces only.** Signing uses RFC 6979 via
  `ecdsa_sign_digest`; no `random`/RNG nonce path is introduced. This avoids the
  catastrophic-nonce-reuse failure mode and keeps signatures reproducible in
  tests.
- **No secret material in logs, reprs, errors, or benchmark output.** Private
  scalars never appear in `__repr__`, exception messages, or trace output;
  error messages identify inputs by index/pubkey, never by key.
- **Verify-before-emit** (see §5 post-sign) so a miscomputed sighash cannot
  produce a silently invalid or wrong-key signature.
- **Amount/prevout binding enforced** so the signer cannot be tricked into
  signing a BIP-143 sighash over an attacker-chosen amount.
- **No network, no filesystem writes** in the signing path.
- Threat-model note added to docs: PSBT partial sigs are not confidential, but
  the signing key and the correctness of the amount binding are the trust
  anchors.

---

## 8. Test strategy

Mirrors the M4.2 test doctrine (official vectors + round-trip + negative +
property + regression), targeting a new `tests/test_psbt_signer.py`.

**Positive / correctness**

- Every official BIP-174 signer vector → byte-exact output PSBT.
- End-to-end BIP-39 path: mnemonic → `keylab.hd` derivation → sign a
  constructed PSBT → verify partial sig with `ecdsa_verify_digest`.
- Segwit-v0 (P2WPKH, P2SH-P2WPKH, P2WSH) and legacy (P2PKH, P2SH) input signing,
  each cross-checked against `bip143_sighash` / legacy sighash.
- Round-trip: `serialize(sign(parse(x)))` parses back equal and re-validates.

**Negative (must raise `PsbtError` / documented error, never sign)**

- Missing required UTXO record; `non_witness_utxo` hash ≠ outpoint;
  inconsistent `witness_utxo` scriptPubKey; wrong/unrelated signing key;
  unsupported sighash flag; already-present partial sig for the same pubkey;
  attempting to sign a structurally invalid PSBT (fails M4.2 `validate` first).

**Property-based (Hypothesis)**

- Additivity: for randomized valid PSBTs + key sets, the signed output differs
  from the input only by added `PSBT_IN_PARTIAL_SIG`/`SIGHASH_TYPE` records on
  signable inputs; all other bytes identical.
- Self-verification: every emitted signature verifies and is low-S/DER-canonical.
- Idempotence: signing an already-signed input with the same key is a no-op or a
  defined refusal (no duplicate/clobber).

**Regression + benchmark**

- Pin one official signer vector as a structural regression test.
- Correctness-gated `benchmark_psbt_sign` (sign over the signer vectors, timed);
  **no optimization work** — benchmark is measurement only, same pattern as
  `benchmark_psbt`.

**Quality gates (same bar as M4.2):** all 11 CI jobs green; `validate_all()`
clean; coverage floor held or raised; mypy ratchet baseline unchanged or
improved; fixture provenance verified; `gen_api_docs.py --check` clean with the
new public names added to `docs/api.md`.

---

## 9. Proposed public API surface (for review, not yet built)

```
keylab.psbt.signer.sign(psbt, keys, *, sighash=SIGHASH_ALL) -> Psbt
keylab.psbt.signer.sign_input(psbt, index, scalar, pubkey, *, sighash=...) -> Psbt
keylab.psbt.signer.signable_inputs(psbt, pubkeys) -> list[int]
keylab.psbt.signer.derive_signing_keys(xkey, psbt) -> dict[bytes, int]   # BIP32-derivation adapter
```

Re-exported from `keylab.psbt` alongside the existing
`parse/serialize/validate/deserialize`. Exact names/signatures are subject to
review at implementation time; this list defines intent and boundary, not a
frozen contract.

---

## 10. Milestone exit criteria

M4.3 is complete when: every official BIP-174 signer vector produces a
byte-exact output PSBT; every emitted signature self-verifies, is low-S/DER
canonical, and round-trips; the negative/property/regression suites pass; all 11
CI jobs are green on the M4.3 PR; SECURITY.md and `feature_audit` reflect
"attaches partial signatures, not a wallet/finalizer/extractor/broadcaster"; and
no finalization, extraction, wallet, research, or Taproot-PSBT code was
introduced.

---

**DO NOT IMPLEMENT (this milestone, per instruction):** PSBT finalization,
transaction extraction, wallet workflows, research tooling. This document is the
plan only; implementation awaits explicit approval to begin M4.3.
