# Security Track — Milestone 2: Crypto Policy — Implementation Plan

**Status:** APPROVED (OQ1–OQ3 resolved; amendments incorporated). Implemented
under the standard gates. Milestone 1 (fuzzing) is merged (`main = 8db7160`); its
corpus-cap follow-up is tracked as issue #25.

**Scope (fixed by the earlier decisions — do not expand):** three items that sit
*alongside* the existing crypto, changing no teaching behavior:
(1) an algorithm allow-list module, (2) a single constant-time compare helper,
(3) HKDF domain-separation documentation + tests. **No AEAD, no password KDF, no
storage, no networking, no HSM** (§9). `SECURITY.md` is not edited; if something
forces it, stop and ask.

**No new dependencies (confirmed):** the allow-list uses stdlib types only
(frozensets, strings, ints); `constant_time_equal` wraps stdlib
`hmac.compare_digest`; no `cryptography`/`pycryptodome` in the new code (those
remain optional differential backends, not dependencies of the policy module).

**Reporting language (fixed):** this milestone is "crypto-policy primitives +
constant-time helper consolidation," **not** "crypto hardening." The only
behavior-touching change is the two-site constant-time refactor, which is
behavior-preserving.

---

## 1. Current surfaces the policy will sit alongside

Verified in the repo at planning time:

- **`keylab.crypto`** already provides: `hkdf(ikm, length, *, salt=b"", info=b"",
  hash_name="sha256")` (RFC 5869, SHA-256/512); RSA — `generate_rsa_keypair(bits=2048)`,
  `rsa_pss_sign`/`rsa_pss_verify` (PSS, not PKCS#1 v1.5), `rsa_oaep_encrypt`/
  `rsa_oaep_decrypt`. These are already modern choices.
- **Teaching asymmetric crypto** in `keylab.ec`: `secp256k1` (`ecdsa_sign_digest`
  — deterministic, low-S), `schnorr` (BIP-340), `musig2` (BIP-327 key agg). All
  carry the existing "readable, not constant-time; use a reviewed native impl for
  production" warning.
- **Constant-time compare** is *already used ad hoc* via `hmac.compare_digest` in
  `keylab/hashes/mac.py` and `keylab/advanced_suite.py` (2 sites). There is no
  single shared helper and no centralized algorithm policy today.

This milestone adds a centralized allow-list these choices can be *checked
against* (zero production callers — §2), and consolidates the constant-time
compare into one leaf helper (`keylab/_ct.py`) reused by the existing sites. It
introduces **no** new cryptographic operations and changes **no** teaching
behavior.

---

## 2. Algorithm allow-list module

New `keylab/crypto_policy.py` (small, centralized, data + pure checks — no
user/config-driven selection beyond the allow-list):

- **Allow-list data (frozensets/constants):**
  - hashes: `{"sha256", "sha384", "sha512"}`; SHA-1/MD5 rejected.
  - signature schemes: `{"ecdsa-secp256k1", "schnorr-bip340", "rsa-pss-sha256"}`;
    `rsa-pkcs1v15` explicitly **not** allowed for new signatures.
  - RSA: minimum modulus **2048** bits (advisory constant; see caller status).
  - (No AEAD/symmetric category — omitted until a future milestone has an actual
    consumer; a placeholder empty set would be dead code. Per OQ3 → (b).)
- **Pure check functions** that raise a typed `PolicyError` (or return bool), e.g.
  `require_hash(name)`, `is_allowed_hash(name)`, `require_rsa_key_bits(bits)`,
  `require_signature_scheme(name)`. No side effects, no I/O.

**Caller status (explicit): zero production callers this milestone.** The
allow-list is a standalone library primitive. Existing public functions (`hkdf`,
`rsa_*`, `ecdsa_*`, Schnorr, MuSig2) keep their exact signatures and behavior and
gain **no** policy checks. Per **OQ1 → (b)**, the allow-list stays **advisory
only, with no call-path change** — in particular `generate_rsa_keypair` does
**not** gain an RSA key-size guard. Rationale (recorded): this is a teaching
library, and teaching code legitimately generates small RSA keys (e.g. 512-bit)
to keep the math tractable; a `<2048` guard would break a future teaching example
or a user following the docs even though no current test exercises it. The "no
change to existing teaching-crypto behavior" invariant wins. If such a guard is
ever wanted it must be **opt-in** (`strict=True` kwarg, or a separate
`generate_rsa_keypair_strict`), and that decision belongs to a future milestone —
**noted for the record, not implemented here.**

The allow-list is therefore exercised **only by tests** asserting that every
choice KeyLab already makes is a member and that disallowed inputs are rejected
by the check functions. It is a *library primitive, not a runtime control*, in
this milestone. Nothing here is presented as hardening existing code via the
allow-list; the only behavior-touching change is the constant-time-helper refactor
in §3.

## 3. Constant-time compare helper

- A single `keylab/_ct.py` leaf module exposing
  `constant_time_equal(a: bytes, b: bytes) -> bool`, wrapping `hmac.compare_digest`
  (the stdlib constant-time primitive). Per **OQ2 → (b)** it lives in `_ct.py`, a
  dependency-free leaf — not in `crypto_policy` — so a hash/MAC module never has
  to depend on the policy module (correct dependency direction). An optional
  convenience re-export from `keylab.crypto_policy` is permitted but not required.
- **Reuse:** refactor the 2 existing `hmac.compare_digest` call sites
  (`keylab/hashes/mac.py`, `keylab/advanced_suite.py`) to import and call
  `constant_time_equal`.
- **Refactor audit (amendment 2):** for each site the diff must be **mechanical**
  — replace the `hmac.compare_digest(...)` call with `constant_time_equal(...)`,
  no other change — and the module's **existing tests must be untouched and still
  pass**. If any existing test needs editing to accommodate the refactor, that is
  a **finding: stop and report; do not adjust the test to fit.**
- **Testing:**
  - Named regression cases: equal; equal-length-differing; **different-length**
    (must return `False`, not raise, not short-circuit into an exception);
    non-bytes (type guard rejects cleanly).
  - **Property test (amendment 1):** `@given(st.binary(), st.binary())` asserting
    `constant_time_equal(a, b) == (a == b)` for all byte pairs (subsumes and
    strengthens the enumerated set).
  - Wall-clock timing invariance is a property of the stdlib primitive and is
    **not** re-measured in CI (timing tests are flaky); documented, not faked.

## 4. HKDF domain-separation

- No API change to `hkdf` (it already takes `info`). Add:
  - **Docs:** a short "domain separation" note (in `docs/` and the `hkdf`
    docstring) explaining that distinct `info` strings derive independent keys
    from the same IKM, and that callers deriving multiple keys from one master
    secret must use distinct `info` labels.
  - **Tests (four cases):**
    1. same IKM + different `info` → different outputs (several label pairs);
    2. same IKM + same `info` + same params → identical output (determinism);
    3. same IKM + same `info` + different `salt` → different output;
    4. **(amendment 3)** same IKM + same `info` + same `salt` + different
       `hash_name` (`sha256` vs `sha512`) → different output.
  - No change to existing callers; existing HKDF tests must not regress.

---

## 5. "Teaching, not production" warnings

Every new symbol (`crypto_policy` module, `constant_time_equal`) carries the same
disclaimer style already used for ECDSA/Schnorr/MuSig2: readable/reference code,
not constant-time-audited beyond the stdlib primitive it wraps, no secure
erasure. The allow-list documents *what KeyLab considers acceptable for study*,
not a certification of the implementations.

---

## 6. Exit criteria (numbers)

- `keylab/crypto_policy.py` added with ≥3 allow-list classes (hashes, signature
  schemes, RSA key size) and their check functions; `keylab/_ct.py` added with
  `constant_time_equal`.
- **Caller status (stated, not implied):** the allow-list ships with **zero
  production callers** — a library primitive exercised only by tests, not a
  runtime control over existing code. `constant_time_equal` is the only new symbol
  wired into existing code (2 sites, behavior-preserving).
- **Every algorithm KeyLab already uses passes the allow-list** (asserted by
  test): HKDF `sha256`/`sha512`; RSA default 2048 + PSS; ECDSA-secp256k1;
  Schnorr-BIP340. ≥6 such positive assertions.
- **≥6 disallowed inputs rejected** by the policy (e.g. `sha1`, `md5`,
  `rsa-pkcs1v15`, RSA 1024, unknown scheme).
- `constant_time_equal`: ≥4 named regression cases (incl. different-length and
  non-bytes) **plus** the `st.binary()×st.binary()` property test; the 2 existing
  call sites refactored to use it with a mechanical diff and **no existing test
  edited**.
- HKDF domain-separation: **4 cases** (distinct-info, determinism, distinct-salt,
  distinct-hash_name) pass; **no existing HKDF test regresses**.
- Gates: **12 CI jobs green** (any `fuzz-extended` dispatches reported
  separately); `validate_all()` = 0; coverage floor held or raised; mypy baseline
  (99) unchanged or improved; `gen_api_docs --check` clean with the new public
  names; `vectors.py verify` unaffected.
- No `SECURITY.md` edit; no change to existing teaching-crypto behavior; no new
  dependency.

## 7. Test plan (new `tests/test_crypto_policy.py` + `tests/test_ct.py`)

Positive allow-list membership; negative rejections (raise `PolicyError`);
`constant_time_equal` named cases + property test + type guard; refactor
regression (mac/OAEP paths still verify, their existing tests unedited); HKDF
domain-separation four cases. Hypothesis: `constant_time_equal(a,b)==(a==b)` for
random byte pairs; for random IKM and distinct info/hash_name, HKDF outputs
differ.

## 8. Risks

- **Scope creep toward AEAD/KDF** — explicitly fenced (§9); any temptation goes to
  a future milestone, not this PR.
- **Refactor of existing compare sites** — low risk (same primitive); the
  refactor-audit rule (mechanical diff, existing tests unedited) makes any
  deviation a reported finding rather than a silent test change.
- **mypy baseline** — new modules must be typed so the ratchet does not regress.
- **Dependency direction** — `_ct.py` is a leaf (OQ2) so hash/MAC modules do not
  depend on the policy module.

## 9. Out of scope and resolved decisions

**Out of scope (unchanged):** AEAD (AES-GCM/ChaCha20-Poly1305), password KDFs
(Argon2id/scrypt/bcrypt), encrypted storage, networking/TLS, HSM/KMS. These stay
out of this PR.

**Resolved decisions (no longer open):**
- **OQ1 → (b):** allow-list is advisory only, zero production callers, no
  call-path change; `generate_rsa_keypair` gains no key-size guard (teaching code
  may use small RSA keys). Any future guard must be opt-in and is deferred.
- **OQ2 → (b):** `constant_time_equal` lives in `keylab/_ct.py` (leaf), imported
  by the policy module and the two existing call sites; policy-module re-export
  optional.
- **OQ3 → (b):** no AEAD/symmetric allow-list category; it is added only when a
  future milestone has an actual AEAD consumer.

---

**Process:** implement in reviewable commits (this plan-doc commit →
`_ct.py` + tests → `crypto_policy.py` + tests → two-site refactor → HKDF docs +
tests → report), gates after each, then report with changed files, commands,
results, and numeric exit-criteria outcomes (including the property test and the
fourth HKDF case).

READY — IMPLEMENTING UNDER STANDARD GATES
