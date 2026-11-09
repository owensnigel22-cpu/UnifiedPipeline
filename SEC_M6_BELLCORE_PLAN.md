# SEC_M6 — Bellcore fault attacks (simulated) (PLAN)

Status: **PLAN ONLY — no code.** Per the standing rule (plan doc → ack → code →
gates → merge). Nothing here changes behaviour. **M7 (read-only mainnet) is not
started.**

Sequence position: after M5 merged to `main` (`441cd35`). M6 is next.

---

## 0. Honest framing (simulated, not physical)

A **Bellcore fault attack** (Boneh–DeMillo–Lipton, 1997) recovers a private key
when a signing device produces **one correct and one faulty** signature of the
same message, because the fault leaks a modular relationship the correct output
hides. **Real Bellcore attacks require physical fault injection** — voltage
glitching, clock tampering, laser/EM pulses — to corrupt an intermediate value
mid-computation. **This module has no physical capability and performs no such
attack.** It **simulates the mathematical consequence** of a fault by
deliberately corrupting an intermediate value *in software*, then recovers the
key from the correct/faulty pair — demonstrating *why* unprotected CRT-RSA and
ECDSA signers must verify their output before releasing it.

It threatens nothing that is computed correctly: given two correct signatures it
recovers nothing. The mitigation it motivates is concrete: **verify every
signature before output** (CRT-RSA: recompute `s^e mod n == m`; ECDSA: the signer
already self-verifies in KeyLab).

---

## 1. Verify-before-acting: what exists (do NOT regenerate)

| Capability | Where | Status |
|---|---|---|
| Modular exponentiation, `gcd`, Miller-Rabin, factoring | `keylab.numtheory` (`modular_pow`, `batch_gcd`, `pollard_rho_factor`, `fermat_factor`) | ✅ exists |
| RSA public/private round-trip, key recovery, Wiener, Håstad | `keylab.numtheory.rsa` | ✅ exists |
| Deterministic ECDSA sign/verify (RFC 6979, low-S) | `keylab.ec.secp256k1.ecdsa_sign_digest` / `ecdsa_verify_digest` | ✅ exists |
| RFC 6979 nonce + algebraic nonce recovery | `keylab.ec.rfc6979`, `keylab.research.ecdsa.recover_nonce_from_signature` | ✅ M4/A |

**Genuinely new (the real M6 work):**
- A **CRT-RSA signer with optional fault injection** (KeyLab has no CRT signer).
- A **fault-injecting ECDSA signing path** (the stock signer self-verifies and
  does not expose intermediates).
- The two **recovery functions** and the `keylab.research.fault_attacks` package.

---

## 2. Module layout

```
src/keylab/research/fault_attacks/
  __init__.py
  rsa_crt.py        CRT-RSA signer (optional fault) + recover prime from a faulty sig
  ecdsa_fault.py    ECDSA signer (optional fault) + recover d from correct/faulty pair
```

No new namespaces beyond `keylab.research.fault_attacks`. **No new dependencies**
(`math`, `secrets`, `hashlib` suffice). No heavy loops: RSA recovery is one
`gcd`; ECDSA recovery is a 2×2 modular solve — so no brute force and no resource
guards are needed (unlike M5).

---

## 3. Part A — CRT-RSA fault attack

### The maths
CRT signing computes `s = CRT(s_p, s_q)` with `s_p = m^{d_p} mod p`,
`s_q = m^{d_q} mod q`, recombined by Garner's formula
`s = s_q + q·(q_inv·(s_p − s_q) mod p)`. If a fault corrupts the **p-branch**
(`s_p → s_p'`), the faulty `s'` satisfies `s' ≡ s (mod q)` but `s' ≢ s (mod p)`.
Therefore `q | (s − s')` and `p ∤ (s − s')`, so:

```
q = gcd(s − s', n)      p = n / q      d = e^{-1} mod lcm(p−1, q−1)
```

### Functions (proposed)
```python
def rsa_crt_sign(message: int, p: int, q: int, d_p: int, d_q: int, q_inv: int,
                 *, fault: FaultSpec | None = None) -> int: ...
def recover_primes_from_crt_fault(correct_sig: int, faulty_sig: int, n: int,
                                  e: int = 65537) -> CRTFaultResult: ...   # (p, q, d)
```
- `fault` deliberately corrupts `s_p` (or `s_q`) by a stated amount (e.g. flip a
  bit / add a delta) — a software stand-in for a glitch; the docstring says so.
- Recovery returns `None`/raises if `gcd` is trivial (`1` or `n`) — i.e. the pair
  is not a genuine single-branch fault — never a wrong factor.

---

## 4. Part B — ECDSA fault attack

### The maths
Sign the same `z` **twice with the same nonce `k`** (deterministic RFC 6979 gives
the same `k`): a **correct** `(r, s)` with `r = (kG)_x` and `s = k^{-1}(z + r d)`,
and a **faulty** `(r_f, s_f)` where a fault in the scalar multiplication makes the
signer use a wrong `r_f` while still using the correct `k` in
`s_f = k^{-1}(z + r_f d)`. The two equations `s k = z + r d`, `s_f k = z + r_f d`
are linear in `(k, d)`; eliminating `k`:

```
d = z·(s − s_f) · (s_f·r − s·r_f)^{-1}  mod n
```

No brute force, no knowledge of the fault magnitude — a 2×2 modular solve.
(An alternative, a known-delta fault on `d`, is noted but the scalar-mult fault
above is cleaner and fully determined.)

### Functions (proposed)
```python
def ecdsa_sign_with_fault(digest: bytes, d: int,
                          *, fault: FaultSpec | None = None) -> tuple[int, int]: ...
def recover_private_key_from_ecdsa_fault(digest: bytes, r: int, s: int,
                                         r_faulty: int, s_faulty: int) -> int | None: ...
```
- The faulting signer exposes the raw `(r, s)` (no low-S normalisation, so the
  linear relation holds exactly) and shares the nonce between the correct and
  faulty call.
- Recovery forward-verifies `d·G == public_key` (optional arg) and returns
  `None` on a degenerate denominator — never a wrong key.

---

## 5. Tests (independent reference = the planted key)
- **RSA-CRT**: generate a small RSA keypair (Miller-Rabin prime gen, e.g. two
  256-bit primes), CRT-sign a message correctly and with a p-branch fault,
  recover `q = gcd(s−s', n)`, derive `p, d`, and assert `(p, q)` are the planted
  primes and `d` is the planted private exponent (sign/verify round-trips).
- **ECDSA**: generate a keypair, sign a digest correctly and with a scalar-mult
  fault (same nonce), recover `d`, and assert `d` equals the planted key and
  `d·G == public_key`.
- **Negative**: two *correct* signatures recover nothing (degenerate → `None`);
  a trivial `gcd` (no real fault) → `None`; input validation (non-int, out of
  range) raises.
- All always-run (the maths is O(1); RSA keygen uses small primes for speed).

## 6. Docs
`docs/fault_attacks.md`: the Bellcore result, the explicit statement that **real
attacks need physical fault injection** and this module simulates only the
**mathematical consequence**, the CRT `gcd` and ECDSA 2×2 derivations, and the
mitigation (**verify before output**). Journal entry with the measured recovery.

## 7. Exit criteria
- RSA-CRT: planted `(p, q, d)` recovered from one faulty signature; `gcd`-based.
- ECDSA: planted `d` recovered from a correct/faulty pair; `d·G == public_key`.
- Negative cases return `None`, never a wrong key/factor.
- All 12 CI jobs green; ruff + mypy + api docs; no new dependency.

## 8. Risks
- **Over-claiming**: docstrings/docs state plainly this is a *software simulation*
  of the fault's maths, not a physical attack, and recovers nothing from correct
  output.
- **RSA keygen cost**: small primes (≤256-bit) keep tests fast; the attack maths
  is independent of key size.
- **ECDSA low-S / determinism**: the faulting signer returns raw `s` and reuses
  the nonce so the linear relation is exact; the stock `ecdsa_sign_digest` is
  untouched.

## 9. Out of scope
Physical fault injection; attacks on real devices/HSMs; faults the maths cannot
pin down (multi-branch RSA faults, random-nonce ECDSA faults without a shared
nonce); **M7 (read-only mainnet verification) — not started**; any new dependency.

---

Awaiting ack before writing M6 code.
