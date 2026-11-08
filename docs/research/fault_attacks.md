# Bellcore fault attacks (simulated) — `keylab.research.fault_attacks`

Two classic fault attacks (Boneh–DeMillo–Lipton, 1997), shown as **software
simulations of the mathematical consequence** of a fault. Neither performs a
physical attack, and neither recovers anything from correctly-computed output.
See [../../SECURITY.md](../../SECURITY.md).

## Physical vs mathematical (read this first)

A **real** Bellcore attack requires **physical fault injection** — voltage
glitching, clock tampering, under-powering, or a laser/EM pulse aimed at the chip
— to corrupt an intermediate value *while the device signs*. That is a hardware
capability this project does **not** have and does **not** provide.

What this module does instead: it **deliberately corrupts an intermediate value
in software** (a half-signature in CRT-RSA, the point `R` in ECDSA) to reproduce
the exact *algebraic* situation a glitch would create — one correct and one
faulty signature of the same message — and then recovers the key from that pair.
It is a lens on **why** the maths breaks, not a tool for attacking real devices.

**Mitigation (the lesson):** a signer must **verify its own output before
releasing it** — CRT-RSA: check `s^e mod n == m`; ECDSA: re-verify `(r, s)`
(KeyLab's stock `ecdsa_sign_digest` already self-verifies). A verified signature
never leaks the key, so the attack is defeated for free.

## CRT-RSA fault → factor the modulus

CRT signing computes `s = CRT(s_p, s_q)` with `s_p = m^{d_p} mod p`,
`s_q = m^{d_q} mod q`. A fault in the **p-branch** leaves the q-branch correct, so
the faulty `s'` satisfies `s' ≡ s (mod q)` but `s' ≢ s (mod p)`. Hence `q` divides
`s − s'` and `p` does not:

```
q = gcd(s − s', n)      p = n / q      d = e^{-1} mod lcm(p−1, q−1)
```

`keylab.research.fault_attacks.recover_primes_from_crt_fault(correct, faulty, n, e)`
returns `(p, q, d)`, or `None` when the `gcd` is trivial (not a genuine
single-branch fault) — never a wrong factor. `rsa_crt_sign(..., fault_branch='p')`
injects the simulated fault.

## ECDSA fault → solve a 2×2 system

Sign the same digest twice with the **same nonce** `k` (deterministic RFC 6979): a
correct `(r, s)` with `r = (kG)_x`, `s = k^{-1}(z + r d)`, and a faulty `(r_f, s_f)`
where a glitch in the scalar multiplication makes `r_f ≠ r` while the correct `k`
is still used in `s_f = k^{-1}(z + r_f d)`. The two equations

```
s·k = z + r·d        s_f·k = z + r_f·d
```

are linear in `(k, d)`; eliminating `k`:

```
d = z·(s − s_f) · (s_f·r − s·r_f)^{-1}  mod n
```

No brute force and no knowledge of the fault magnitude — a direct 2×2 modular
solve. `recover_private_key_from_ecdsa_fault(digest, r, s, r_f, s_f, public_key=...)`
returns `d` (forward-verified against the public key), or `None` when the
denominator is zero (e.g. two correct signatures). `ecdsa_sign_with_fault(digest,
d, fault_delta=...)` injects the simulated scalar-multiplication glitch.

## What this does not do

No physical fault injection; no attack on real devices, HSMs, or anyone else's
keys; nothing against correctly-computed signatures (two correct outputs recover
nothing). These are reproducible teaching demonstrations of published maths, with
every recovery checked against the planted key.
