#!/usr/bin/env python3
"""
pass_a_ext_and_advanced_crypto-v17.py
Unified ECC, RSA, Address Diagnostics, Walkback, WIF, and Signature Demonstration Suite (v17)

Security note: educational demonstration only. This handwritten implementation is
not constant-time, has no independent cryptographic review, and must not protect
real keys or funds. The CLI uses a fixed public demo key for traces.

New Features & Additions in v17:
1. RFC 6979 Deterministic Nonce Derivation Engine (--rfc6979-trace):
   - Computes a deterministic nonce k from the private key and message hash.
2. BIP-340 Schnorr Signatures & Taproot Verification (--schnorr-trace):
   - Implements x-only public key derivation (even y-parity enforcement).
   - Zero scalar inversions (s^-1) during verification: s*G == R + e*P directly.
3. Hash-to-Curve Try-and-Increment Engine (--hash-to-curve "seed"):
   - Maps arbitrary string/seed to candidate x-coordinates on secp256k1.
   - Solves y^2 = x^3 + 7 mod P via modular square root y = (x^3 + 7)^((P+1)/4) mod P.
4. Deterministically Derived Point Generator (--verifiable-point "seed"):
   - Derives Q = Hash(P0, seed) * G using a custom, non-standard derivation.
5. MuSig2 Multi-Party Key Aggregation Engine (--musig2-aggregate):
   - Aggregates multiple Schnorr public keys P_1, P_2, ... into a single Taproot key P_agg.
6. Taproot Tweak Engine (--taproot-tweak):
   - Computes the Taproot output public key Q = P + tG.
7. Elliptic-Curve Demonstration Sequence (--ec-prng):
   - Generates deterministic points; this is not a cryptographic PRNG.
8. Forward public-point stepping from an existing key (--pubkey-advance), WIF
   address derivation, Bech32 checksum diagnosis, custom ECDSA signing, and benchmarks.
9. RSA key generation, OAEP encryption/decryption, PSS signing/verification, and
   key parameter analysis (--rsa-* options).
14. Layered address/hash/public-key walkback and DIMACS CNF solving (--sat-cnf).
10. Curve coordinate lifting/intersection and point substitution checks
    (--decompress-y, --intersection, --substitute-y-x).
11. Modular inverse, inverse group multiplication, and scalar bit tracing
    (--mod-inv, --mult-neg-g, --trace-scalar/--russian-mult).
12. Elliptic-curve secant/tangent addition, y=x substitution analysis,
    integer shift-and-add trace, bounded Fermat RSA factor search, and candidate
    factor checks (--curve-add, --y-equals-x, --integer-mult, --rsa-*).
13. SHA-256 forward trace and conditional backward state ledger, plus modular
    shift-and-add multiplication (--sha256-trace, --sha256-backward-ledger).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import math
import secrets
import time

# =============================================================================
# secp256k1 Constants & Core Elliptic Curve Operations
# =============================================================================

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
)

_SHA256_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
              0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
_SHA256_K = (
    0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
    0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
    0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
    0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
    0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
    0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
    0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
    0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2,
)

def sha256_compression_trace(message: bytes) -> dict[str, object]:
    """FIPS 180-4 SHA-256 trace, with each block's 64 forward round states."""
    if len(message) >= (1 << 61):
        raise ValueError("SHA-256 message must be shorter than 2^64 bits")
    bit_length = len(message) * 8
    padded = bytearray(message)
    padded.append(0x80)
    padded.extend(b"\x00" * ((56 - len(padded) % 64) % 64))
    padded.extend(bit_length.to_bytes(8, "big"))
    state = list(_SHA256_IV)
    block_traces = []
    mask = 0xFFFFFFFF

    def rotr(x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & mask

    for block_index in range(0, len(padded), 64):
        block = padded[block_index:block_index + 64]
        schedule = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
        for i in range(16, 64):
            s0 = rotr(schedule[i - 15], 7) ^ rotr(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3)
            s1 = rotr(schedule[i - 2], 17) ^ rotr(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10)
            schedule.append((schedule[i - 16] + s0 + schedule[i - 7] + s1) & mask)
        a, b, c, d, e, f, g, h = state
        round_states = []
        for i in range(64):
            big1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            choose = (e & f) ^ ((~e) & g)
            t1 = (h + big1 + choose + _SHA256_K[i] + schedule[i]) & mask
            big0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            t2 = (big0 + majority) & mask
            a, b, c, d, e, f, g, h = (t1 + t2) & mask, a, b, c, (d + t1) & mask, e, f, g
            round_states.append(tuple(f"{word:08x}" for word in (a,b,c,d,e,f,g,h)))
        state = [(old + new) & mask for old, new in zip(state, (a,b,c,d,e,f,g,h))]
        block_traces.append({"block_index": block_index // 64,
                             "input_state": [f"{v:08x}" for v in _SHA256_IV] if not block_traces else block_traces[-1]["output_state"],
                             "schedule": [f"{v:08x}" for v in schedule],
                             "round_states": round_states,
                             "output_state": [f"{v:08x}" for v in state]})
    digest = "".join(f"{word:08x}" for word in state)
    reference = hashlib.sha256(message).hexdigest()
    if digest != reference:
        raise ArithmeticError("internal SHA-256 trace disagrees with hashlib")
    return {"digest_hex": digest, "matches_hashlib": True, "padded_blocks": block_traces}

def sha256_backward_ledger(digest_hex: str, block_hex: str | None = None) -> dict[str, object]:
    """Explore SHA-256's last compression round, optionally reversing a known block.

    Digest-only mode is explicitly conditional on a one-block padded message,
    so the final chaining state is the standard SHA-256 IV. Supplying the exact
    64-byte final compression block permits a full, verifiable round reversal.
    """
    try:
        digest = bytes.fromhex(digest_hex.removeprefix("0x"))
    except ValueError as exc:
        raise ValueError("digest must be 64 hexadecimal characters") from exc
    if len(digest) != 32:
        raise ValueError("digest must be exactly 32 bytes")
    digest_words = [int.from_bytes(digest[i:i + 4], "big") for i in range(0, 32, 4)]
    target_state = [(d - iv) & 0xFFFFFFFF for d, iv in zip(digest_words, _SHA256_IV)]
    state_hex = lambda words: [f"{word:08x}" for word in words]

    def rotr(x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    result: dict[str, object] = {
        "assumption": "digest is from exactly one padded 512-bit block compressed from the standard IV",
        "final_working_state": state_hex(target_state),
        "message_words_known": block_hex is not None,
        "fully_reversed": False,
        "state_classification": {
            "final_working_state": "numerically derived, conditional on the one-block/standard-IV assumption",
            "last_round_previous_state": "partially numeric; h63 remains symbolic in W63",
            "earlier_rounds": "unresolved without message-schedule constraints",
        },
    }
    if block_hex is None:
        a1, b1, c1, d1, e1, f1, g1, h1 = target_state
        old_a, old_b, old_c = b1, c1, d1
        old_e, old_f, old_g = f1, g1, h1
        big0 = rotr(old_a, 2) ^ rotr(old_a, 13) ^ rotr(old_a, 22)
        maj = (old_a & old_b) ^ (old_a & old_c) ^ (old_b & old_c)
        t1 = (a1 - ((big0 + maj) & 0xFFFFFFFF)) & 0xFFFFFFFF
        old_d = (e1 - t1) & 0xFFFFFFFF
        big1 = rotr(old_e, 6) ^ rotr(old_e, 11) ^ rotr(old_e, 25)
        ch = (old_e & old_f) ^ ((~old_e) & old_g)
        old_h_expression = (
            f"T1_63 - Sigma1(e63) - Ch(e63,f63,g63) - K63 - W63 mod 2^32; "
            f"T1_63=0x{t1:08x}"
        )
        result["last_round_recovered_state"] = {
            "a63": f"0x{old_a:08x}", "b63": f"0x{old_b:08x}",
            "c63": f"0x{old_c:08x}", "d63": f"0x{old_d:08x}",
            "e63": f"0x{old_e:08x}", "f63": f"0x{old_f:08x}",
            "g63": f"0x{old_g:08x}", "h63": old_h_expression,
            "unknown": "W63 (the final expanded message-schedule word)"
        }
        result["boundary"] = "Earlier rounds depend on unresolved W63 and message-schedule constraints."
        return result

    try:
        block = bytes.fromhex(block_hex.removeprefix("0x"))
    except ValueError as exc:
        raise ValueError("block must be 128 hexadecimal characters") from exc
    if len(block) != 64:
        raise ValueError("block must be exactly 64 bytes (one SHA-256 compression block)")
    words = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for i in range(16, 64):
        s0 = rotr(words[i - 15], 7) ^ rotr(words[i - 15], 18) ^ (words[i - 15] >> 3)
        s1 = rotr(words[i - 2], 17) ^ rotr(words[i - 2], 19) ^ (words[i - 2] >> 10)
        words.append((words[i - 16] + s0 + words[i - 7] + s1) & 0xFFFFFFFF)
    a, b, c, d, e, f, g, h = _SHA256_IV
    forward = []
    for i in range(64):
        big1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        t1 = (h + big1 + ch + _SHA256_K[i] + words[i]) & 0xFFFFFFFF
        big0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (big0 + maj) & 0xFFFFFFFF
        a, b, c, d, e, f, g, h = (t1 + t2) & 0xFFFFFFFF, a, b, c, (d + t1) & 0xFFFFFFFF, e, f, g
        forward.append((a,b,c,d,e,f,g,h))
    computed_digest = b"".join(((iv + work) & 0xFFFFFFFF).to_bytes(4, "big")
                                for iv, work in zip(_SHA256_IV, (a,b,c,d,e,f,g,h))).hex()
    if computed_digest != digest.hex():
        raise ValueError("provided block does not compress from the standard IV to the supplied digest")

    current = list(target_state)
    for i in range(63, -1, -1):
        a1, b1, c1, d1, e1, f1, g1, h1 = current
        old_a, old_b, old_c = b1, c1, d1
        old_e, old_f, old_g = f1, g1, h1
        big0 = rotr(old_a, 2) ^ rotr(old_a, 13) ^ rotr(old_a, 22)
        maj = (old_a & old_b) ^ (old_a & old_c) ^ (old_b & old_c)
        t1 = (a1 - ((big0 + maj) & 0xFFFFFFFF)) & 0xFFFFFFFF
        old_d = (e1 - t1) & 0xFFFFFFFF
        big1 = rotr(old_e, 6) ^ rotr(old_e, 11) ^ rotr(old_e, 25)
        ch = (old_e & old_f) ^ ((~old_e) & old_g)
        old_h = (t1 - big1 - ch - _SHA256_K[i] - words[i]) & 0xFFFFFFFF
        current = [old_a,old_b,old_c,old_d,old_e,old_f,old_g,old_h]
    result.update({"fully_reversed": True, "recovered_initial_state": state_hex(current),
                   "matches_standard_iv": tuple(current) == _SHA256_IV,
                   "state_classification": {
                       "final_working_state": "numerically recovered",
                       "intermediate_round_states": "numerically recovered using the exact block schedule",
                       "initial_state": "numerically recovered and compared with the standard IV",
                   },
                   "boundary": "All rounds reversed using the supplied exact message block."})
    return result

def run_extended_joint_lookahead_sweep() -> list[dict[str, object]]:
    """Return v10's illustrative density sweep as a synthetic planning model.

    These estimates are not generated by a SAT solver and must not be read as
    measured propagation or cryptanalytic results.
    """
    total_vars, total_clauses = 210, 582
    records = []
    for depth in (0, 2, 4, 8, 12, 16, 24, 32, 48, 64):
        remaining_vars = max(total_vars - depth, 146)
        eliminated_clauses = int(depth * 2.64)
        remaining_clauses = max(total_clauses - eliminated_clauses, 413)
        records.append({
            "cube_depth_bits": depth,
            "remaining_vars": remaining_vars,
            "remaining_clauses": remaining_clauses,
            "clause_density_alpha": round(remaining_clauses / remaining_vars, 4),
            "illustrative_unit_propagation_rate_pct": round(depth / 64 * 100, 1),
            "evidence_kind": "synthetic estimate; no SAT/CNF solver run",
        })
    return records

def field_inv(n: int, p: int = SECP256K1_P) -> int:
    """Base field coordinate multiplicative inverse via Fermat's Little Theorem."""
    n %= p
    if n == 0:
        raise ValueError("zero has no multiplicative inverse")
    return pow(n, p - 2, p)

def eea_mod_inv(a: int, m: int = SECP256K1_P) -> int:
    """Fast single modular inverse via Extended Euclidean Algorithm (~2.5x faster than Fermat)."""
    if m <= 0:
        raise ValueError("Modulus m must be positive")
    old_r, r = a % m, m
    old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    if old_r > 1:
        raise ValueError(f"Multiplicative inverse does not exist: gcd({a}, {m}) = {old_r} != 1")
    return old_s % m

def batch_inv(vals: list[int], p: int = SECP256K1_P) -> list[int]:
    """
    Montgomery Batch Inversion: Computes modular inverses for k elements in parallel
    using 1 modular exponentiation + 3(k-1) multiplications (~40x faster).
    """
    if not vals:
        return []
    prod = [1]
    for v in vals:
        v_non_zero = v if v != 0 else 1
        prod.append((prod[-1] * v_non_zero) % p)
    
    inv = pow(prod[-1], p - 2, p)
    res = []
    for i in range(len(vals) - 1, -1, -1):
        v_non_zero = vals[i] if vals[i] != 0 else 1
        res.append((inv * prod[i]) % p)
        inv = (inv * v_non_zero) % p
    return [0 if value % p == 0 else inverse for value, inverse in zip(vals, reversed(res))]

def scalar_inv(d: int, n: int = SECP256K1_N) -> int:
    """Scalar multiplicative inverse d^(-1) mod N via Fermat's Little Theorem."""
    return pow(d, n - 2, n)

def point_negate(pt: tuple[int, int]) -> tuple[int, int]:
    """Group additive inverse -P = (x, P - y mod P)."""
    return (pt[0], (-pt[1]) % SECP256K1_P)

def jacobian_double(p1: tuple[int, int, int]) -> tuple[int, int, int]:
    """Fast Point Doubling in Jacobian Projective coordinates (a=0)."""
    X1, Y1, Z1 = p1
    if Y1 == 0:
        return (0, 0, 0)
    S = (4 * X1 * Y1**2) % SECP256K1_P
    M = (3 * X1**2) % SECP256K1_P
    X3 = (M**2 - 2 * S) % SECP256K1_P
    Y3 = (M * (S - X3) - 8 * Y1**4) % SECP256K1_P
    Z3 = (2 * Y1 * Z1) % SECP256K1_P
    return (X3, Y3, Z3)

def jacobian_add(p1: tuple[int, int, int], p2: tuple[int, int, int]) -> tuple[int, int, int]:
    """Full Point Addition in Jacobian Projective coordinates."""
    if p1[2] == 0:
        return p2
    if p2[2] == 0:
        return p1
    X1, Y1, Z1 = p1
    X2, Y2, Z2 = p2
    U1 = (X1 * Z2**2) % SECP256K1_P
    U2 = (X2 * Z1**2) % SECP256K1_P
    S1 = (Y1 * Z2**3) % SECP256K1_P
    S2 = (Y2 * Z1**3) % SECP256K1_P
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 0)
        return jacobian_double(p1)
    H = (U2 - U1) % SECP256K1_P
    R = (S2 - S1) % SECP256K1_P
    H2 = (H * H) % SECP256K1_P
    H3 = (H * H2) % SECP256K1_P
    X3 = (R**2 - H3 - 2 * U1 * H2) % SECP256K1_P
    Y3 = (R * (U1 * H2 - X3) - S1 * H3) % SECP256K1_P
    Z3 = (H * Z1 * Z2) % SECP256K1_P
    return (X3, Y3, Z3)

def jacobian_add_mixed(p1: tuple[int, int, int], p2_aff: tuple[int, int]) -> tuple[int, int, int]:
    """Optimized Mixed Point Addition (Jacobian + Affine)."""
    if p1[2] == 0:
        return (p2_aff[0], p2_aff[1], 1)
    if p2_aff == (0, 0):
        return p1
    X1, Y1, Z1 = p1
    X2, Y2 = p2_aff
    Z1_2 = (Z1 * Z1) % SECP256K1_P
    U2 = (X2 * Z1_2) % SECP256K1_P
    S2 = (Y2 * Z1 * Z1_2) % SECP256K1_P
    if X1 == U2:
        if Y1 != S2:
            return (0, 0, 0)
        return jacobian_double(p1)
    H = (U2 - X1) % SECP256K1_P
    R = (S2 - Y1) % SECP256K1_P
    H2 = (H * H) % SECP256K1_P
    H3 = (H * H2) % SECP256K1_P
    X3 = (R**2 - H3 - 2 * X1 * H2) % SECP256K1_P
    Y3 = (R * (X1 * H2 - X3) - Y1 * H3) % SECP256K1_P
    Z3 = (H * Z1) % SECP256K1_P
    return (X3, Y3, Z3)

def jacobian_to_affine(p1: tuple[int, int, int]) -> tuple[int, int]:
    """Converts Jacobian projective point (X, Y, Z) to Affine (x, y)."""
    X, Y, Z = p1
    if Z == 0:
        return (0, 0)
    z_inv = eea_mod_inv(Z, SECP256K1_P)
    z_inv2 = (z_inv * z_inv) % SECP256K1_P
    z_inv3 = (z_inv2 * z_inv) % SECP256K1_P
    return ((X * z_inv2) % SECP256K1_P, (Y * z_inv3) % SECP256K1_P)

# =============================================================================
# Precomputed Fixed 4-Bit Affine Window Table for Generator G
# =============================================================================

_G_PRECOMP_AFFINE: list[list[tuple[int, int]]] = []

def _init_g_precomp_table():
    """Initializes fixed 4-bit affine window table for generator G at startup."""
    if _G_PRECOMP_AFFINE:
        return
    
    G_JAC = (SECP256K1_G[0], SECP256K1_G[1], 1)
    curr = G_JAC
    all_jac = []
    
    for window in range(64):
        table_w = [(0, 0, 0)]
        table_w.append(curr)
        for mult in range(2, 16):
            table_w.append(jacobian_add(table_w[-1], curr))
        all_jac.append(table_w)
        for _ in range(4):
            curr = jacobian_double(curr)

    z_coords = []
    for w in range(64):
        for mult in range(1, 16):
            z_coords.append(all_jac[w][mult][2])

    inv_z = batch_inv(z_coords, SECP256K1_P)
    
    idx = 0
    for w in range(64):
        table_aff = [(0, 0)]
        for mult in range(1, 16):
            zi = inv_z[idx]
            idx += 1
            zi2 = (zi * zi) % SECP256K1_P
            zi3 = (zi2 * zi) % SECP256K1_P
            X, Y, _ = all_jac[w][mult]
            table_aff.append(((X * zi2) % SECP256K1_P, (Y * zi3) % SECP256K1_P))
        _G_PRECOMP_AFFINE.append(table_aff)

def scalar_mult_g_fast(k: int) -> tuple[int, int]:
    """Optimized fixed-base scalar multiplication k * G using 4-bit affine window table."""
    k %= SECP256K1_N
    if k == 0:
        return (0, 0)
    if not _G_PRECOMP_AFFINE:
        _init_g_precomp_table()
    R = (0, 0, 0)
    for window in range(64):
        val = (k >> (4 * window)) & 0xF
        if val > 0:
            R = jacobian_add_mixed(R, _G_PRECOMP_AFFINE[window][val])
    return jacobian_to_affine(R)

def compute_naf(k: int) -> list[int]:
    """Derives Non-Adjacent Form (NAF) signed binary representation for scalar k."""
    if k < 0:
        raise ValueError("NAF input must be non-negative")
    naf = []
    while k > 0:
        if k % 2 == 1:
            ki = 2 - (k % 4)
            k -= ki
        else:
            ki = 0
        naf.append(ki)
        k //= 2
    return naf

def scalar_mult_naf_jacobian(k: int, pt: tuple[int, int]) -> tuple[int, int, int]:
    """Multiply an arbitrary point without converting the result to affine form."""
    if k < 0:
        return scalar_mult_naf_jacobian(-k, point_negate(pt))
    k %= SECP256K1_N
    if k == 0:
        return (0, 0, 0)
    naf = compute_naf(k)
    P_jac = (pt[0], pt[1], 1)
    P_neg_jac = (pt[0], (-pt[1]) % SECP256K1_P, 1)
    R_jac = (0, 0, 0)
    
    for val in reversed(naf):
        R_jac = jacobian_double(R_jac)
        if val == 1:
            R_jac = jacobian_add(R_jac, P_jac)
        elif val == -1:
            R_jac = jacobian_add(R_jac, P_neg_jac)
            
    return R_jac

def scalar_mult_naf(k: int, pt: tuple[int, int] = SECP256K1_G) -> tuple[int, int]:
    """Performs scalar point multiplication k * P using NAF or fast table lookup."""
    if pt == SECP256K1_G and k >= 0:
        return scalar_mult_g_fast(k)
    return jacobian_to_affine(scalar_mult_naf_jacobian(k, pt))

def is_on_curve(pt: tuple[int, int]) -> bool:
    x, y = pt
    return 0 <= x < SECP256K1_P and 0 <= y < SECP256K1_P and (y * y - x * x * x - 7) % SECP256K1_P == 0

def lift_x_even(x: int) -> tuple[int, int]:
    """Decode a BIP-340 x-only public key to the curve point with even y."""
    if not 0 <= x < SECP256K1_P:
        raise ValueError("public-key x coordinate is outside the field")
    c = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    y = pow(c, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if y * y % SECP256K1_P != c:
        raise ValueError("x coordinate does not lift to a secp256k1 point")
    return (x, y if y % 2 == 0 else SECP256K1_P - y)

def parse_pubkey(pubkey_hex: str) -> tuple[int, int]:
    """Parse a 32-byte x-only or 33-byte SEC compressed secp256k1 public key."""
    raw = bytes.fromhex(pubkey_hex.removeprefix("0x"))
    if len(raw) == 32:
        return lift_x_even(int.from_bytes(raw, "big"))
    if len(raw) != 33 or raw[0] not in (2, 3):
        raise ValueError("public key must be 32-byte x-only or 33-byte compressed SEC hex")
    x = int.from_bytes(raw[1:], "big")
    pt = lift_x_even(x)
    return pt if raw[0] == 2 or pt[1] % 2 == 0 else point_negate(pt)

def curve_y_roots(x: int) -> tuple[int, ...]:
    """Return the curve's y-coordinate root(s) for x, or raise if x has no point."""
    if not 0 <= x < SECP256K1_P:
        raise ValueError("x coordinate must be in [0, p)")
    rhs = (pow(x, 3, SECP256K1_P) + 7) % SECP256K1_P
    y = pow(rhs, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if y * y % SECP256K1_P != rhs:
        raise ValueError("x coordinate does not lift to a secp256k1 point")
    other = (-y) % SECP256K1_P
    return (y,) if y == other else tuple(sorted((y, other)))

def scalar_multiplication_trace(k: int, pt: tuple[int, int] = SECP256K1_G) -> dict[str, object]:
    """Educational left-to-right double-and-add trace for a nonnegative scalar."""
    if k < 0:
        raise ValueError("scalar trace requires a nonnegative scalar")
    if not is_on_curve(pt):
        raise ValueError("input point is not on secp256k1")
    result = (0, 0, 0)
    rows = []
    for bit_index, bit in enumerate(bin(k)[2:] if k else "0"):
        result = jacobian_double(result)
        did_add = bit == "1"
        if did_add:
            result = jacobian_add_mixed(result, pt)
        rows.append({"bit_index": bit_index, "bit": int(bit), "added_point": did_add})
    return {"scalar": k, "bit_length": k.bit_length(), "hamming_weight": k.bit_count(),
            "result": jacobian_to_affine(result), "steps": rows}

def modular_inverse_report(value: int, modulus: int) -> dict[str, int]:
    """Compute an inverse when gcd(value, modulus)=1 and report the gcd."""
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")
    gcd_value = math.gcd(value, modulus)
    if gcd_value != 1:
        raise ValueError(f"inverse does not exist: gcd(value, modulus) = {gcd_value}")
    inverse = pow(value, -1, modulus)
    return {"value": value, "modulus": modulus, "gcd": gcd_value, "inverse": inverse,
            "check": (value * inverse) % modulus}

def curve_add_geometry(p1: tuple[int, int], p2: tuple[int, int]) -> dict[str, object]:
    """Return the secant/tangent line and elliptic-curve sum of two points."""
    for point in (p1, p2):
        if point != (0, 0) and not is_on_curve(point):
            raise ValueError("both input points must be on secp256k1 (use (0,0) for infinity)")
    if p1 == (0, 0):
        return {"slope": None, "third_intersection": p2, "sum": p2}
    if p2 == (0, 0):
        return {"slope": None, "third_intersection": p1, "sum": p1}
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % SECP256K1_P == 0:
        return {"slope": None, "third_intersection": (0, 0), "sum": (0, 0)}
    if p1 == p2:
        if y1 == 0:
            return {"slope": None, "third_intersection": (x1, 0), "sum": (0, 0)}
        slope = (3 * x1 * x1 * pow(2 * y1, -1, SECP256K1_P)) % SECP256K1_P
    else:
        slope = ((y2 - y1) * pow((x2 - x1) % SECP256K1_P, -1, SECP256K1_P)) % SECP256K1_P
    x3 = (slope * slope - x1 - x2) % SECP256K1_P
    y_line = (slope * (x3 - x1) + y1) % SECP256K1_P
    third = (x3, y_line)
    total = (x3, (-y_line) % SECP256K1_P)
    return {"slope": slope, "third_intersection": third, "sum": total}

def y_equals_x_report(x: int) -> dict[str, int | bool]:
    """Evaluate the curve equation after substituting y=x, in the base field."""
    x %= SECP256K1_P
    residual = (pow(x, 3, SECP256K1_P) + 7 - pow(x, 2, SECP256K1_P)) % SECP256K1_P
    return {"x": x, "residual": residual, "is_curve_point": residual == 0}

def russian_integer_multiply(a: int, b: int) -> dict[str, object]:
    """Trace binary shift-and-add multiplication, including signed operands."""
    sign = -1 if (a < 0) ^ (b < 0) else 1
    multiplicand, multiplier = abs(a), abs(b)
    rows, total = [], 0
    while multiplier:
        bit = multiplier & 1
        if bit:
            total += multiplicand
        rows.append({"multiplicand": multiplicand, "multiplier": multiplier,
                     "bit": bit, "partial_sum": total})
        multiplicand <<= 1
        multiplier >>= 1
    return {"product": sign * total, "steps": rows}

def russian_modular_multiply(a: int, b: int, modulus: int) -> dict[str, object]:
    """Compute a*b mod m by binary shift-and-add with bounded residues."""
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    sign = -1 if (a < 0) ^ (b < 0) else 1
    x, y = abs(a) % modulus, abs(b)
    total, rows = 0, []
    while y:
        bit = y & 1
        if bit:
            total = (total + x) % modulus
        rows.append({"addend": x, "multiplier": y, "bit": bit, "residue": total})
        x = (2 * x) % modulus
        y >>= 1
    result = (sign * total) % modulus
    if result != (a * b) % modulus:
        raise ArithmeticError("modular multiplication trace verification failed")
    return {"result": result, "steps": rows, "verified": True}

def fermat_factor(n: int, max_steps: int = 100_000) -> dict[str, object]:
    """Bounded Fermat search; succeeds quickly only when odd factors are close."""
    if n <= 1 or n % 2 == 0:
        raise ValueError("Fermat search requires an odd integer greater than 1")
    if max_steps < 0:
        raise ValueError("max_steps must be nonnegative")
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for step in range(max_steps + 1):
        delta = a * a - n
        b = math.isqrt(delta)
        if b * b == delta:
            p, q = a - b, a + b
            if p > 1 and p * q == n:
                return {"found": True, "p": p, "q": q, "steps": step}
        a += 1
    return {"found": False, "steps": max_steps, "limit": max_steps}

def rsa_factor_candidate_report(n: int, p: int, q: int, e: int = 65537) -> dict[str, object]:
    """Check a proposed RSA factor pair and exponent compatibility."""
    if n <= 1 or p <= 1 or q <= 1 or e <= 1:
        raise ValueError("n, p, q, and e must be integers greater than 1")
    product_matches = p * q == n
    p_probable_prime = _is_probable_prime(p) if product_matches else False
    q_probable_prime = _is_probable_prime(q) if product_matches else False
    exponent_coprime = math.gcd(e, math.lcm(p - 1, q - 1)) == 1 if product_matches else False
    return {"product_matches": product_matches, "p_probable_prime": p_probable_prime,
            "q_probable_prime": q_probable_prime, "exponent_coprime_to_lambda": exponent_coprime,
            "candidate_valid": product_matches and p_probable_prime and q_probable_prime and exponent_coprime}

def compress_pubkey(pt: tuple[int, int]) -> bytes:
    """Derives 33-byte SEC compressed public key byte array."""
    x, y = pt
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return prefix + x.to_bytes(32, 'big')

def batch_jacobian_to_affine(points: list[tuple[int, int, int]]) -> list[tuple[int, int]]:
    """Convert many Jacobian points with one batch inversion."""
    if not points:
        return []
    z_inverses = batch_inv([point[2] for point in points], SECP256K1_P)
    result = []
    for (x, y, z), z_inv in zip(points, z_inverses):
        if z == 0:
            result.append((0, 0))
            continue
        z_inv2 = z_inv * z_inv % SECP256K1_P
        z_inv3 = z_inv2 * z_inv % SECP256K1_P
        result.append((x * z_inv2 % SECP256K1_P, y * z_inv3 % SECP256K1_P))
    return result

def advance_public_key(pubkey_hex: str, steps: int = 10) -> dict[str, object]:
    """Advance a public point by repeatedly adding G, with batched output conversion.

    This is public-point arithmetic Q_i = Q_(i-1) + G. It is not BIP32 derivation,
    and it does not recover or reveal a private key.
    """
    if not 1 <= steps <= 1000:
        raise ValueError("steps must be between 1 and 1000")
    point = parse_pubkey(pubkey_hex)
    current = (point[0], point[1], 1)
    walked = []
    for _ in range(steps):
        current = jacobian_add_mixed(current, SECP256K1_G)
        walked.append(current)
    affine_points = batch_jacobian_to_affine(walked)
    return {
        "start_pubkey_hex": compress_pubkey(point).hex(),
        "steps": [
            {"index": index, "point_at_infinity": pt == (0, 0),
             "compressed_pubkey_hex": None if pt == (0, 0) else compress_pubkey(pt).hex()}
            for index, pt in enumerate(affine_points, start=1)
        ],
    }

# =============================================================================
# RFC 6979 Deterministic Nonce Generator Engine
# =============================================================================

def rfc6979_deterministic_nonce(privkey_d: int, hash_z: int) -> int:
    """
    Derives a deterministic ephemeral nonce using the RFC 6979 procedure.
    The result is reproducible for a given private key and message hash.
    """
    if not 1 <= privkey_d < SECP256K1_N:
        raise ValueError("private key must be in [1, n-1]")
    d_bytes = privkey_d.to_bytes(32, 'big')
    h_bytes = (hash_z % SECP256K1_N).to_bytes(32, 'big')
    V = b'\x01' * 32
    K = b'\x00' * 32
    
    K = hmac.new(K, V + b'\x00' + d_bytes + h_bytes, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b'\x01' + d_bytes + h_bytes, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k_candidate = int.from_bytes(V, 'big')
        if 1 <= k_candidate < SECP256K1_N:
            return k_candidate
        K = hmac.new(K, V + b'\x00', hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()

def rfc6979_trace(privkey_d: int, msg_str: str) -> dict[str, object]:
    """Traces RFC 6979 deterministic nonce generation."""
    z = int.from_bytes(hashlib.sha256(msg_str.encode('utf-8')).digest(), 'big')
    k_det = rfc6979_deterministic_nonce(privkey_d, z)
    R_pt = scalar_mult_g_fast(k_det)
    return {
        "msg_input": msg_str,
        "hash_z_hex": f"0x{z:064x}",
        "rfc6979_k_hex": f"0x{k_det:064x}",
        "ephemeral_R_affine": R_pt,
        "deterministic_for_key_and_hash": True
    }

# =============================================================================
# BIP-340 Schnorr Signatures & Taproot Engine
# =============================================================================

def tagged_hash(tag: str, msg_bytes: bytes) -> bytes:
    """Computes BIP-340 Tagged Hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    tag_digest = hashlib.sha256(tag.encode('utf-8')).digest()
    return hashlib.sha256(tag_digest + tag_digest + msg_bytes).digest()

def schnorr_bip340_sign_and_verify_trace(
    privkey_d: int, msg_str: str, aux_rand: bytes = b"\x00" * 32
) -> dict[str, object]:
    """
    Executes a complete BIP-340 Schnorr signature generation and verification trace:
    1. Enforces x-only public key (even y-parity).
    2. Generates the BIP-340 nonce using tagged aux and nonce hashes.
    3. Computes challenge e via tagged hash BIP0340/challenge.
    4. Computes signature s = (k + e * d) mod N.
    5. Verifies s * G == R + e * P directly (NO SCALAR INVERSION s^-1 REQUIRED!).
    """
    if not 1 <= privkey_d < SECP256K1_N:
        raise ValueError("private key must be in [1, n-1]")
    if len(aux_rand) != 32:
        raise ValueError("BIP-340 auxiliary randomness must be exactly 32 bytes")
    msg_bytes = msg_str.encode('utf-8')
    if len(msg_bytes) != 32:
        raise ValueError("BIP-340 messages must be exactly 32 bytes; pass a 32-byte hex message via a future CLI option")
    
    P = scalar_mult_g_fast(privkey_d)
    d = privkey_d
    if P[1] % 2 != 0:
        d = SECP256K1_N - d
        P = point_negate(P)

    d_bytes = d.to_bytes(32, 'big')
    aux_hash = tagged_hash("BIP0340/aux", aux_rand)
    t = bytes(a ^ b for a, b in zip(d_bytes, aux_hash))
    k_bytes = tagged_hash("BIP0340/nonce", t + P[0].to_bytes(32, 'big') + msg_bytes)
    k = int.from_bytes(k_bytes, 'big') % SECP256K1_N
    if k == 0:
        raise ValueError("Invalid zero nonce derived")

    R = scalar_mult_g_fast(k)
    if R[1] % 2 != 0:
        k = SECP256K1_N - k
        R = point_negate(R)

    e_bytes = tagged_hash("BIP0340/challenge", R[0].to_bytes(32, 'big') + P[0].to_bytes(32, 'big') + msg_bytes)
    e = int.from_bytes(e_bytes, 'big') % SECP256K1_N

    s = (k + e * d) % SECP256K1_N

    sG = scalar_mult_g_fast(s)
    eP_jac = scalar_mult_naf_jacobian(e, P)
    R_plus_eP_jac = jacobian_add((R[0], R[1], 1), eP_jac)
    R_plus_eP = jacobian_to_affine(R_plus_eP_jac)

    verified = (sG == R_plus_eP)

    return {
        "x_only_pubkey_P_hex": f"0x{P[0]:064x}",
        "P_y_even": (P[1] % 2 == 0),
        "msg_input": msg_str,
        "nonce_k_hex": f"0x{k:064x}",
        "R_x_hex": f"0x{R[0]:064x}",
        "challenge_e_hex": f"0x{e:064x}",
        "sig_s_hex": f"0x{s:064x}",
        "sG_affine": sG,
        "R_plus_eP_affine": R_plus_eP,
        "verified": verified,
        "zero_inversions_required": True,
        "aux_rand_hex": aux_rand.hex(),
    }

def ecdsa_sign_and_verify_trace(privkey_d: int, message: str) -> dict[str, object]:
    """Sign a text payload or 0x-prefixed hash with RFC 6979 and verify it."""
    if not 1 <= privkey_d < SECP256K1_N:
        raise ValueError("private key must be in [1, n-1]")
    z = int(message, 16) if message.lower().startswith("0x") else int.from_bytes(hashlib.sha256(message.encode('utf-8')).digest(), 'big')
    k = rfc6979_deterministic_nonce(privkey_d, z)
    R = scalar_mult_g_fast(k)
    r = R[0] % SECP256K1_N
    if r == 0:
        raise ValueError("invalid nonce produced r = 0")
    s = (scalar_inv(k, SECP256K1_N) * (z + r * privkey_d)) % SECP256K1_N
    if s == 0:
        raise ValueError("invalid signature produced s = 0")
    low_s_normalized = s > SECP256K1_N // 2
    if low_s_normalized:
        s = SECP256K1_N - s
    Q = scalar_mult_g_fast(privkey_d)
    w = scalar_inv(s, SECP256K1_N)
    u1, u2 = z * w % SECP256K1_N, r * w % SECP256K1_N
    u1G, u2Q = scalar_mult_g_fast(u1), scalar_mult_naf(u2, Q)
    R_prime = jacobian_to_affine(jacobian_add((u1G[0], u1G[1], 1), (u2Q[0], u2Q[1], 1)))
    return {
        "pubkey_hex": compress_pubkey(Q).hex(),
        "hash_z_hex": f"0x{z:064x}",
        "sig_r_hex": f"0x{r:064x}",
        "sig_s_hex": f"0x{s:064x}",
        "low_s_normalized": low_s_normalized,
        "verified": R_prime != (0, 0) and R_prime[0] % SECP256K1_N == r,
    }

def ecdsa_nonce_reuse_attack_trace(privkey_d: int, reused_k: int) -> dict[str, object]:
    """Educational demonstration: reusing an ECDSA nonce exposes the signing key."""
    if not 1 <= privkey_d < SECP256K1_N or not 1 <= reused_k < SECP256K1_N:
        raise ValueError("private key and nonce must be in [1, n-1]")
    z1 = int.from_bytes(hashlib.sha256(b"Nonce reuse demo message one").digest(), 'big')
    z2 = int.from_bytes(hashlib.sha256(b"Nonce reuse demo message two").digest(), 'big')
    r = scalar_mult_g_fast(reused_k)[0] % SECP256K1_N
    s1 = scalar_inv(reused_k, SECP256K1_N) * (z1 + r * privkey_d) % SECP256K1_N
    s2 = scalar_inv(reused_k, SECP256K1_N) * (z2 + r * privkey_d) % SECP256K1_N
    recovered_k = (z1 - z2) * scalar_inv(s1 - s2, SECP256K1_N) % SECP256K1_N
    recovered_d = (s1 * recovered_k - z1) * scalar_inv(r, SECP256K1_N) % SECP256K1_N
    return {"shared_r_hex": f"0x{r:064x}", "nonce_recovered": recovered_k == reused_k, "private_key_recovered": recovered_d == privkey_d}

# =============================================================================
# Hash-to-Curve & Verifiably Random Point Generators
# =============================================================================

def hash_to_curve_try_and_increment(seed_str: str) -> dict[str, object]:
    """
    Experimental try-and-increment mapping. This is not a standardized hash-to-curve
    suite and must not be used to derive protocol keys.
    Tests candidate x-coordinates and computes modular square root y = (x^3 + 7)^((P+1)/4) mod P.
    """
    counter = 0
    while True:
        candidate_bytes = hashlib.sha256(seed_str.encode('utf-8') + counter.to_bytes(4, 'big')).digest()
        x_candidate = int.from_bytes(candidate_bytes, 'big') % SECP256K1_P
        rhs = (pow(x_candidate, 3, SECP256K1_P) + 7) % SECP256K1_P
        
        # Test for quadratic residue
        if rhs == 0 or pow(rhs, (SECP256K1_P - 1) // 2, SECP256K1_P) == 1:
            y_even = pow(rhs, (SECP256K1_P + 1) // 4, SECP256K1_P)
            pt = (x_candidate, y_even)
            return {
                "seed": seed_str,
                "tries": counter,
                "point_x_hex": f"0x{pt[0]:064x}",
                "point_y_hex": f"0x{pt[1]:064x}",
                "on_curve": pow(pt[1], 2, SECP256K1_P) == (pow(pt[0], 3, SECP256K1_P) + 7) % SECP256K1_P
            }
        counter += 1

def verifiable_pseudorandom_point(seed_str: str) -> dict[str, object]:
    """
    Deterministically derives Q = Hash(P0 || seed) * G. This custom construction
    does not establish a general proof of trapdoor absence or follow a named standard.
    """
    P0_bytes = SECP256K1_G[0].to_bytes(32, 'big')
    seed_bytes = seed_str.encode('utf-8')
    c_hash = hashlib.sha256(P0_bytes + seed_bytes).digest()
    c_scalar = (int.from_bytes(c_hash, 'big') % (SECP256K1_N - 1)) + 1
    
    Q_pt = scalar_mult_g_fast(c_scalar)
    return {
        "seed": seed_str,
        "derived_scalar_c_hex": f"0x{c_scalar:064x}",
        "verifiable_point_Q_x_hex": f"0x{Q_pt[0]:064x}",
        "verifiable_point_Q_y_hex": f"0x{Q_pt[1]:064x}",
        "compressed_pubkey_hex": compress_pubkey(Q_pt).hex(),
        "trust_property": "Reproducibly derived via SHA-256; custom construction, not a protocol standard"
    }

# =============================================================================
# New in v17: MuSig2 Key Aggregation, Taproot Tweaking & Long-Period EC PRNG
# =============================================================================

def musig2_aggregate_keys(pubkey_hex_list: list[str]) -> dict[str, object]:
    """
    MuSig2 Key Aggregation Engine: Aggregates multiple Schnorr public keys into a joint key P_agg.
    Calculates key coefficients a_i = Hash(KeyAgg || P_1 || ... || P_n || P_i) for unforgeability.
    """
    if len(pubkey_hex_list) < 2:
        raise ValueError("provide at least two public keys")
    pts = [lift_x_even(parse_pubkey(p_hex)[0]) for p_hex in pubkey_hex_list]

    # Compute KeyAgg list digest
    list_bytes = b"".join(pt[0].to_bytes(32, 'big') for pt in pts)
    L_hash = tagged_hash("KeyAgg/list", list_bytes)

    # Compute key coefficients a_i and sum a_i * P_i
    R_agg_jac = (0, 0, 0)
    coeffs = []
    xkeys = [pt[0].to_bytes(32, 'big') for pt in pts]
    second_unique = next((key for key in xkeys[1:] if key != xkeys[0]), None)
    for pt, key in zip(pts, xkeys):
        # MuSig2 assigns coefficient 1 to the second distinct key.
        a_i = 1 if key == second_unique else int.from_bytes(tagged_hash("KeyAgg coefficient", L_hash + key), 'big') % SECP256K1_N
        if a_i == 0:
            raise ValueError("MuSig2 key coefficient is zero")
        coeffs.append(f"0x{a_i:064x}")
        
        aP_i_jac = scalar_mult_naf_jacobian(a_i, pt)
        R_agg_jac = jacobian_add(R_agg_jac, aP_i_jac)

    P_agg = jacobian_to_affine(R_agg_jac)
    return {
        "input_pubkeys_count": len(pubkey_hex_list),
        "key_coefficients_a_i": coeffs,
        "aggregated_point_x_hex": f"0x{P_agg[0]:064x}",
        "aggregated_point_y_hex": f"0x{P_agg[1]:064x}",
        "x_only_aggregated_pubkey_hex": f"0x{P_agg[0]:064x}"
    }

def taproot_tweak_pubkey(internal_pubkey_x_hex: str, merkle_root_hex: str = "") -> dict[str, object]:
    """
    Computes Taproot Tweak: Q = P + t*G, where t = TaggedHash("TapTweak", P_x || merkle_root).
    """
    P_internal = lift_x_even(parse_pubkey(internal_pubkey_x_hex)[0])

    m_bytes = bytes.fromhex(merkle_root_hex.replace("0x", "")) if merkle_root_hex else b""
    t_bytes = tagged_hash("TapTweak", P_internal[0].to_bytes(32, 'big') + m_bytes)
    t_scalar = int.from_bytes(t_bytes, 'big')
    if t_scalar >= SECP256K1_N:
        raise ValueError("TapTweak hash is outside the scalar range")

    tG = scalar_mult_g_fast(t_scalar)
    Q_jac = jacobian_add((P_internal[0], P_internal[1], 1), (tG[0], tG[1], 1))
    Q_taproot = jacobian_to_affine(Q_jac)
    if Q_taproot == (0, 0):
        raise ValueError("Taproot tweak produced the point at infinity")

    return {
        "internal_pubkey_x_hex": f"0x{P_internal[0]:064x}",
        "taproot_tweak_t_hex": f"0x{t_scalar:064x}",
        "output_taproot_pubkey_x_hex": f"0x{Q_taproot[0]:064x}",
        "output_taproot_pubkey_y_hex": f"0x{Q_taproot[1]:064x}"
    }

def long_period_ec_prng_generator(seed_str: str, dimension: int = 4) -> dict[str, object]:
    """
    Generates a deterministic demonstration sequence. This LCG-based construction
    is not cryptographically secure and its period is not guaranteed to equal N.
    """
    if not 1 <= dimension <= 1024:
        raise ValueError("dimension must be between 1 and 1024")
    seed_hash = hashlib.sha256(seed_str.encode('utf-8')).digest()
    state_scalar = int.from_bytes(seed_hash, 'big') % SECP256K1_N

    vector = []
    for _ in range(dimension):
        state_scalar = (state_scalar * 0x5deacee9 + 0xb) % SECP256K1_N
        pt = scalar_mult_g_fast(state_scalar)
        vector.append({
            "coord_x_hex": f"0x{pt[0]:064x}",
            "coord_y_hex": f"0x{pt[1]:064x}"
        })

    return {
        "seed": seed_str,
        "dimension": dimension,
        "security_note": "Demonstration only; not a cryptographically secure PRNG",
        "generated_pseudorandom_vectors": vector
    }

def bech32_polymod_diagnose(address: str) -> dict[str, object]:
    """Validate a Bech32/Bech32m checksum and report its HRP and encoding variant."""
    if not 8 <= len(address) <= 90:
        raise ValueError("Bech32 address length must be between 8 and 90 characters")
    if address.lower() != address and address.upper() != address:
        raise ValueError("Bech32 strings cannot mix uppercase and lowercase")
    address = address.lower()
    separator = address.rfind('1')
    if separator < 1 or separator + 7 > len(address):
        raise ValueError("Bech32 separator or checksum position is invalid")
    hrp, encoded = address[:separator], address[separator + 1:]
    if any(not 33 <= ord(ch) <= 126 for ch in hrp):
        raise ValueError("Bech32 human-readable prefix must contain printable ASCII")
    charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    try:
        data = [charset.index(char) for char in encoded]
    except ValueError as exc:
        raise ValueError("Bech32 address contains an invalid data character") from exc
    generators = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    check = 1
    values = [ord(ch) >> 5 for ch in hrp] + [0] + [ord(ch) & 31 for ch in hrp] + data
    for value in values:
        top = check >> 25
        check = ((check & 0x1ffffff) << 5) ^ value
        for bit, generator in enumerate(generators):
            if (top >> bit) & 1:
                check ^= generator
    variant = "bech32" if check == 1 else "bech32m" if check == 0x2bc830a3 else "unknown"
    return {
        "address": address,
        "hrp": hrp,
        "data_length_5bit": len(data) - 6,
        "polymod_residual": f"0x{check:08x}",
        "checksum_variant": variant,
        "valid_checksum": variant != "unknown",
    }

def decode_wif(wif: str) -> dict[str, object]:
    """Decode and validate a Base58Check WIF, then derive its public-key addresses."""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    wif = wif.strip()
    if not wif:
        raise ValueError("WIF value cannot be empty")
    number = 0
    for char in wif:
        try:
            number = number * 58 + alphabet.index(char)
        except ValueError as exc:
            raise ValueError(f"Invalid Base58 character: {char!r}") from exc
    body = number.to_bytes((number.bit_length() + 7) // 8, 'big') if number else b''
    raw = b'\x00' * (len(wif) - len(wif.lstrip('1'))) + body
    if len(raw) not in (37, 38):
        raise ValueError("WIF payload must contain a 32-byte scalar and checksum")
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError("Invalid WIF checksum")
    version = payload[0]
    if version not in (0x80, 0xEF):
        raise ValueError("Unsupported WIF network prefix")
    compressed = len(payload) == 34 and payload[-1] == 1
    if len(payload) != (34 if compressed else 33):
        raise ValueError("Malformed WIF payload or compression marker")
    private_scalar = int.from_bytes(payload[1:33], 'big')
    if not 1 <= private_scalar < SECP256K1_N:
        raise ValueError("WIF private scalar must be in [1, n-1]")
    point = scalar_mult_g_fast(private_scalar)
    compressed_key = compress_pubkey(point)
    serialized = compressed_key if compressed else b'\x04' + point[0].to_bytes(32, 'big') + point[1].to_bytes(32, 'big')
    h160 = hashlib.new('ripemd160', hashlib.sha256(serialized).digest()).digest()
    network_prefix = b'\x00' if version == 0x80 else b'\x6f'
    payload = network_prefix + h160
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    encoded_number = int.from_bytes(payload + check, 'big')
    encoded = []
    while encoded_number:
        encoded_number, digit = divmod(encoded_number, 58)
        encoded.append(alphabet[digit])
    leading_zeroes = len(payload + check) - len((payload + check).lstrip(b'\x00'))
    legacy = '1' * leading_zeroes + ''.join(reversed(encoded))
    segwit = None
    if compressed:
        hrp = 'bc' if version == 0x80 else 'tb'
        charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
        expanded = [ord(ch) >> 5 for ch in hrp] + [0] + [ord(ch) & 31 for ch in hrp]
        data = [0]
        acc = bits = 0
        for byte in h160:
            acc = (acc << 8) | byte
            bits += 8
            while bits >= 5:
                bits -= 5
                data.append((acc >> bits) & 31)
        if bits:
            data.append((acc << (5 - bits)) & 31)
        check_values = expanded + data + [0] * 6
        polymod = 1
        generators = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
        for value in check_values:
            top = polymod >> 25
            polymod = ((polymod & 0x1ffffff) << 5) ^ value
            for bit, generator in enumerate(generators):
                if (top >> bit) & 1:
                    polymod ^= generator
        polymod ^= 1
        checksum_chars = [(polymod >> (5 * (5 - idx))) & 31 for idx in range(6)]
        segwit = hrp + '1' + ''.join(charset[v] for v in data + checksum_chars)
    return {
        "network": "mainnet" if version == 0x80 else "testnet",
        "compressed": compressed,
        "private_key_hex": f"0x{private_scalar:064x}",
        "public_key_hex": serialized.hex(),
        "hash160_hex": h160.hex(),
        "legacy_p2pkh": legacy,
        "native_segwit": segwit,
    }

def _walkback_trace_parse(target: str) -> dict[str, object]:
    """Parse an address/hash/public key and state what public data it reveals.

    The function never claims to recover a private key from a hash or address.
    """
    value = target.strip()
    if not value:
        raise ValueError("walkback target cannot be empty")
    if len(value) == 40:
        try:
            payload = bytes.fromhex(value)
            return {"input": value, "type": "raw HASH160", "hash160_hex": payload.hex(),
                    "public_key_hex": None, "private_key_recoverable": False,
                    "limit": "A HASH160 does not reveal its public key or private key."}
        except ValueError:
            pass
    key_text = value.removeprefix("0x").removeprefix("0X")
    if len(key_text) in (64, 66):
        try:
            point = parse_pubkey(key_text)
            return {"input": value, "type": "public key", "hash160_hex": None,
                    "public_key_hex": compress_pubkey(point).hex(), "private_key_recoverable": False,
                    "limit": "A public key does not reveal its private scalar under the discrete-log assumption."}
        except (ValueError, OverflowError):
            pass
    if '1' in value and value.lower().split('1', 1)[0] in ("bc", "tb", "bcrt"):
        diag = bech32_polymod_diagnose(value)
        if not diag["valid_checksum"]:
            raise ValueError("invalid Bech32 checksum")
        separator = value.lower().rfind('1')
        encoded = value.lower()[separator + 1:]
        charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
        data = [charset.index(ch) for ch in encoded]
        payload5 = data[:-6]
        witness_version = payload5[0]
        acc = bits = 0
        program = bytearray()
        for word in payload5[1:]:
            acc = (acc << 5) | word
            bits += 5
            if bits >= 8:
                bits -= 8
                program.append((acc >> bits) & 0xff)
        if bits >= 5 or ((acc << (8 - bits)) & 0xff):
            raise ValueError("invalid witness program padding")
        if not 2 <= len(program) <= 40 or not 0 <= witness_version <= 16:
            raise ValueError("invalid SegWit witness version or program length")
        if (witness_version == 0 and len(program) not in (20, 32)):
            raise ValueError("version 0 witness program must be 20 or 32 bytes")
        if (witness_version == 0 and diag["checksum_variant"] != "bech32") or (witness_version > 0 and diag["checksum_variant"] != "bech32m"):
            raise ValueError("checksum variant does not match witness version")
        key_hex = program.hex() if witness_version == 1 and len(program) == 32 else None
        return {"input": value, "type": f"SegWit v{witness_version}", "witness_program_hex": program.hex(),
                "public_key_hex": key_hex, "private_key_recoverable": False,
                "limit": "The address encodes a witness program; it does not reveal the private key."}
    # Base58Check legacy P2PKH/P2SH address.
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number = 0
    for char in value:
        try:
            number = number * 58 + alphabet.index(char)
        except ValueError as exc:
            raise ValueError("target is neither a recognized public key, HASH160, nor address") from exc
    body = number.to_bytes((number.bit_length() + 7) // 8, 'big') if number else b''
    raw = b'\x00' * (len(value) - len(value.lstrip('1'))) + body
    if len(raw) != 25 or hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        raise ValueError("invalid Base58Check address")
    version = raw[0]
    kinds = {0x00: "mainnet P2PKH", 0x05: "mainnet P2SH", 0x6f: "testnet P2PKH", 0xc4: "testnet P2SH"}
    if version not in kinds:
        raise ValueError("unsupported Base58Check address version")
    return {"input": value, "type": kinds[version], "hash160_hex": raw[1:21].hex(),
            "public_key_hex": None, "private_key_recoverable": False,
            "limit": "The address contains a HASH160 payload; it cannot be inverted to the key."}

def walkback_trace(target: str) -> dict[str, object]:
    """Return decoded public data with a detailed reverse-path investigation."""
    result = _walkback_trace_parse(target)
    kind = str(result["type"])
    layers = [{"stage": "Target parsing and public encoding", "status": "decoded",
               "data": f"Interpreted as {kind}; encoding/checksum validated where applicable."}]
    public_key = result.get("public_key_hex")
    hash160 = result.get("hash160_hex")
    witness = result.get("witness_program_hex")
    if public_key:
        layers.append({"stage": "Public point to private scalar", "status": "point available; scalar not derived",
                       "data": "The reverse step is the secp256k1 discrete-log equation Q = kG."})
    elif hash160:
        if "P2SH" in kind:
            source = "HASH160(redeem script)"
        elif kind == "SegWit v0" and witness and len(witness) == 64:
            source = "SHA256(witness script)"
        else:
            source = "HASH160(public key)"
        layers.append({"stage": "Address payload to spending data", "status": "payload extracted; preimage unresolved",
                       "data": f"The payload is {source}; its preimage is not contained in the address."})
        if source == "HASH160(public key)":
            layers.append({"stage": "Public key to private scalar", "status": "not reached without a public-key candidate",
                           "data": "A candidate point would still require solving Q = kG."})
    else:
        layers.append({"stage": "Reverse path", "status": "payload unavailable",
                       "data": str(result.get("limit", "No public-key or hash payload was extracted."))})
    result["layers"] = layers
    return result


def solve_cnf(clauses: list[list[int]], variable_count: int, node_limit: int = 100_000) -> dict[str, object]:
    """Dependency-free DPLL solver with unit propagation and pure-literal elimination."""
    if variable_count < 0 or node_limit < 1:
        raise ValueError("variable_count must be nonnegative and node_limit positive")
    if any(lit == 0 or abs(lit) > variable_count for clause in clauses for lit in clause):
        raise ValueError("CNF literal is zero or exceeds the declared variable count")
    stats = {"decisions": 0, "propagations": 0, "nodes": 0}
    def search(assign: dict[int, bool]):
        stats["nodes"] += 1
        if stats["nodes"] > node_limit:
            raise TimeoutError
        while True:
            pending_clauses=[]; unit=None; polarities={}
            for clause in clauses:
                if any(assign.get(abs(lit)) == (lit > 0) for lit in clause if abs(lit) in assign):
                    continue
                pending=[lit for lit in clause if abs(lit) not in assign]
                if not pending:
                    return None
                pending_clauses.append(pending)
                if len(pending)==1:
                    unit=pending[0]; break
                for lit in pending:
                    polarities.setdefault(abs(lit), set()).add(lit > 0)
            if unit is not None:
                assign[abs(unit)] = unit > 0; stats["propagations"] += 1; continue
            if not pending_clauses:
                return assign
            pure=next(((v,next(iter(signs))) for v,signs in polarities.items() if len(signs)==1),None)
            if pure:
                assign[pure[0]]=pure[1]; stats["propagations"] += 1; continue
            break
        freq={}
        for clause in pending_clauses:
            for lit in clause: freq[abs(lit)]=freq.get(abs(lit),0)+1
        var=max(freq,key=freq.get); stats["decisions"] += 1
        for val in (True,False):
            branch=dict(assign); branch[var]=val
            answer=search(branch)
            if answer is not None: return answer
        return None
    try:
        model=search({}); status="SAT" if model is not None else "UNSAT"
    except TimeoutError:
        model=None; status="UNKNOWN (node limit reached)"
    return {"status":status,"model":model,**stats,"clauses":len(clauses),"variables":variable_count}


def parse_dimacs_cnf(text: str) -> tuple[int, list[list[int]]]:
    """Read a DIMACS CNF instance."""
    nvars=nclauses=None; clauses=[]; pending=[]
    for line_no,line in enumerate(text.splitlines(),1):
        line=line.strip()
        if not line or line.startswith('c'): continue
        fields=line.split()
        if fields[0]=='p':
            if nvars is not None or len(fields)!=4 or fields[1]!='cnf': raise ValueError(f"invalid DIMACS header at line {line_no}")
            nvars,nclauses=int(fields[2]),int(fields[3]); continue
        if nvars is None: raise ValueError("DIMACS clauses must follow a p cnf header")
        for value in fields:
            lit=int(value)
            if lit==0: clauses.append(pending); pending=[]
            else: pending.append(lit)
    if nvars is None or pending or len(clauses)!=nclauses: raise ValueError("DIMACS header/clause count mismatch")
    if any(abs(lit)>nvars for clause in clauses for lit in clause): raise ValueError("DIMACS literal outside declared variable range")
    return nvars,clauses

def run_performance_benchmark(trials: int = 8) -> dict[str, object]:
    """Compare the optimized fixed-base path with generic NAF and inversion paths."""
    if not 1 <= trials <= 100:
        raise ValueError("benchmark trials must be between 1 and 100")
    scalars = [int.from_bytes(hashlib.sha256(f"benchmark:{i}".encode()).digest(), 'big') % SECP256K1_N for i in range(trials)]
    # Warm up the lazy precomputation before timing either path.
    scalar_mult_g_fast(scalars[0])
    start = time.perf_counter()
    generic = [jacobian_to_affine(scalar_mult_naf_jacobian(k, SECP256K1_G)) for k in scalars]
    generic_seconds = time.perf_counter() - start
    start = time.perf_counter()
    optimized = [scalar_mult_g_fast(k) for k in scalars]
    optimized_seconds = time.perf_counter() - start
    if generic != optimized:
        raise RuntimeError("benchmark paths produced different public points")
    values = [int.from_bytes(hashlib.sha256(f"inverse:{i}".encode()).digest(), 'big') % SECP256K1_P or 1 for i in range(32)]
    start = time.perf_counter()
    [pow(v, SECP256K1_P - 2, SECP256K1_P) for v in values]
    individual_seconds = time.perf_counter() - start
    start = time.perf_counter()
    batch_inv(values, SECP256K1_P)
    batch_seconds = time.perf_counter() - start
    return {
        "trials": trials,
        "generic_naf_seconds": generic_seconds,
        "fixed_base_seconds": optimized_seconds,
        "fixed_base_speedup_percent": ((generic_seconds / optimized_seconds) - 1) * 100 if optimized_seconds else 0.0,
        "individual_inversions_seconds": individual_seconds,
        "batch_inversions_seconds": batch_seconds,
        "batch_inversion_speedup_percent": ((individual_seconds / batch_seconds) - 1) * 100 if batch_seconds else 0.0,
        "points_match": True,
    }

# =============================================================================
# RSA Toolkit: educational RSA-OAEP and RSA-PSS operations (RFC 8017)
# =============================================================================

def _mgf1(seed: bytes, length: int, hash_fn=hashlib.sha256) -> bytes:
    """Mask generation function MGF1."""
    if length < 0 or length > (1 << 32) * hash_fn().digest_size:
        raise ValueError("invalid MGF1 output length")
    output = bytearray()
    for counter in range((length + hash_fn().digest_size - 1) // hash_fn().digest_size):
        output.extend(hash_fn(seed + counter.to_bytes(4, 'big')).digest())
    return bytes(output[:length])

def _is_probable_prime(n: int, rounds: int = 32) -> bool:
    """Miller-Rabin probable-prime check with small-prime trial division."""
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)
    if n < 2:
        return False
    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def _generate_prime(bits: int, exponent: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if math.gcd(candidate - 1, exponent) == 1 and _is_probable_prime(candidate):
            return candidate

def rsa_generate_keypair(bits: int = 2048, exponent: int = 65537) -> dict[str, int]:
    """Generate an RSA keypair. Educational implementation; not constant-time."""
    if not 2048 <= bits <= 4096 or bits % 2:
        raise ValueError("RSA modulus size must be an even number from 2048 to 4096 bits")
    if exponent < 3 or exponent % 2 == 0:
        raise ValueError("RSA public exponent must be an odd integer >= 3")
    half = bits // 2
    while True:
        p = _generate_prime(half, exponent)
        q = _generate_prime(half, exponent)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        lam = math.lcm(p - 1, q - 1)
        if math.gcd(exponent, lam) == 1:
            d = pow(exponent, -1, lam)
            return {"n": n, "e": exponent, "d": d, "p": p, "q": q}

def rsa_key_info(n: int, e: int, d: int | None = None, p: int | None = None, q: int | None = None) -> dict[str, object]:
    """Inspect supplied RSA parameters and report consistency/capacity checks."""
    if n <= 3 or n % 2 == 0:
        raise ValueError("RSA modulus must be a positive odd integer")
    if e < 3 or e >= n or e % 2 == 0:
        raise ValueError("RSA public exponent must be an odd integer >= 3")
    factors_match = None if p is None or q is None else p * q == n
    private_exponent_consistent = None
    if p is not None and q is not None and d is not None and factors_match:
        private_exponent_consistent = (e * d) % math.lcm(p - 1, q - 1) == 1
    key_bytes = (n.bit_length() + 7) // 8
    return {
        "modulus_bits": n.bit_length(),
        "modulus_bytes": key_bytes,
        "public_exponent": e,
        "oaep_sha256_max_message_bytes": max(0, key_bytes - 2 * hashlib.sha256().digest_size - 2),
        "at_least_2048_bits": n.bit_length() >= 2048,
        "factor_product_matches_modulus": factors_match,
        "private_exponent_consistent": private_exponent_consistent,
    }

def rsa_oaep_encrypt(message: bytes, n: int, e: int, label: bytes = b"") -> bytes:
    """Encrypt bytes with RSAES-OAEP using SHA-256 and a fresh random seed."""
    if n <= 3 or n % 2 == 0 or e < 3 or e >= n or e % 2 == 0:
        raise ValueError("invalid RSA public key")
    h_len = hashlib.sha256().digest_size
    k = (n.bit_length() + 7) // 8
    if k < 2 * h_len + 2:
        raise ValueError("RSA key is too small for OAEP/SHA-256")
    if len(message) > k - 2 * h_len - 2:
        raise ValueError(f"message too long for this RSA key; maximum is {k - 2 * h_len - 2} bytes")
    l_hash = hashlib.sha256(label).digest()
    db = l_hash + b'\x00' * (k - len(message) - 2 * h_len - 2) + b'\x01' + message
    seed = secrets.token_bytes(h_len)
    db_mask = _mgf1(seed, k - h_len - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = _mgf1(masked_db, h_len)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    encoded = b'\x00' + masked_seed + masked_db
    m = int.from_bytes(encoded, 'big')
    if m >= n:
        raise ValueError("encoded message is outside the RSA modulus")
    return pow(m, e, n).to_bytes(k, 'big')

def rsa_oaep_decrypt(ciphertext: bytes, n: int, d: int, label: bytes = b"") -> bytes:
    """Decrypt RSAES-OAEP/SHA-256 bytes. Python big integers are not constant-time."""
    if n <= 3 or n % 2 == 0 or not 1 <= d < n:
        raise ValueError("invalid RSA private key")
    h_len = hashlib.sha256().digest_size
    k = (n.bit_length() + 7) // 8
    if k < 2 * h_len + 2:
        raise ValueError("RSA key is too small for OAEP/SHA-256")
    c = int.from_bytes(ciphertext, 'big')
    if len(ciphertext) != k or c >= n:
        raise ValueError("ciphertext has invalid length or value")
    encoded = pow(c, d, n).to_bytes(k, 'big')
    if encoded[0] != 0:
        raise ValueError("OAEP decoding failed")
    masked_seed = encoded[1:1 + h_len]
    masked_db = encoded[1 + h_len:]
    seed_mask = _mgf1(masked_db, h_len)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask = _mgf1(seed, k - h_len - 1)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    l_hash = hashlib.sha256(label).digest()
    if not hmac.compare_digest(db[:h_len], l_hash):
        raise ValueError("OAEP decoding failed")
    delimiter = db.find(b'\x01', h_len)
    if delimiter < 0 or any(db[h_len:delimiter]):
        raise ValueError("OAEP decoding failed")
    return db[delimiter + 1:]

def rsa_pss_sign(message: bytes, n: int, d: int, salt_length: int = 32) -> bytes:
    """Sign bytes using RSASSA-PSS/SHA-256 and a random salt."""
    if n <= 3 or n % 2 == 0 or not 1 <= d < n:
        raise ValueError("invalid RSA private key")
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    h_len = hashlib.sha256().digest_size
    if salt_length < 0 or em_len < h_len + salt_length + 2:
        raise ValueError("RSA key is too small for the selected PSS salt length")
    m_hash = hashlib.sha256(message).digest()
    salt = secrets.token_bytes(salt_length)
    h_value = hashlib.sha256(b'\x00' * 8 + m_hash + salt).digest()
    db = b'\x00' * (em_len - h_len - salt_length - 2) + b'\x01' + salt
    masked_db = bytearray(a ^ b for a, b in zip(db, _mgf1(h_value, em_len - h_len - 1)))
    masked_db[0] &= 0xff >> (8 * em_len - em_bits)
    encoded = bytes(masked_db) + h_value + b'\xbc'
    signature = pow(int.from_bytes(encoded, 'big'), d, n)
    return signature.to_bytes((n.bit_length() + 7) // 8, 'big')

def rsa_pss_verify(message: bytes, signature: bytes, n: int, e: int, salt_length: int = 32) -> bool:
    """Verify RSASSA-PSS/SHA-256 with the specified salt length."""
    if n <= 3 or n % 2 == 0 or e < 3 or e >= n or e % 2 == 0:
        return False
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    sig_value = int.from_bytes(signature, 'big')
    if sig_value >= n:
        return False
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    h_len = hashlib.sha256().digest_size
    if salt_length < 0 or em_len < h_len + salt_length + 2:
        return False
    encoded = pow(sig_value, e, n).to_bytes(k, 'big')
    if em_len != len(encoded):
        encoded = encoded[-em_len:]
    if encoded[-1] != 0xbc:
        return False
    masked_db, h_value = encoded[:em_len - h_len - 1], encoded[em_len - h_len - 1:-1]
    unused_bits = 8 * em_len - em_bits
    if unused_bits and masked_db[0] >> (8 - unused_bits):
        return False
    db = bytearray(a ^ b for a, b in zip(masked_db, _mgf1(h_value, em_len - h_len - 1)))
    db[0] &= 0xff >> unused_bits
    padding_len = em_len - h_len - salt_length - 2
    if any(db[:padding_len]) or db[padding_len] != 1:
        return False
    salt = bytes(db[-salt_length:]) if salt_length else b''
    expected = hashlib.sha256(b'\x00' * 8 + hashlib.sha256(message).digest() + salt).digest()
    return hmac.compare_digest(h_value, expected)

def rsa_demo(bits: int = 2048) -> dict[str, object]:
    """Run ephemeral OAEP encryption/decryption and PSS signing/verification."""
    key = rsa_generate_keypair(bits)
    info = rsa_key_info(key['n'], key['e'], key['d'], key['p'], key['q'])
    message = b"RSA OAEP/PSS demonstration"
    ciphertext = rsa_oaep_encrypt(message, key['n'], key['e'])
    recovered = rsa_oaep_decrypt(ciphertext, key['n'], key['d'])
    signature = rsa_pss_sign(message, key['n'], key['d'])
    return {
        "key_info": info,
        "ciphertext_hex": ciphertext.hex(),
        "decrypt_matches": recovered == message,
        "signature_hex": signature.hex(),
        "signature_verified": rsa_pss_verify(message, signature, key['n'], key['e']),
    }

# =============================================================================
# CLI Main Entrypoint
# =============================================================================

def bip340_message_arg(value: str) -> str:
    if len(value.encode('utf-8')) != 32:
        raise argparse.ArgumentTypeError("BIP-340 message must encode to exactly 32 UTF-8 bytes")
    return value

def main():
    parser = argparse.ArgumentParser(description="Unified Cryptanalytic, Diagnostic, Multiplicative, Geometry, Walkback, WIF, ECDSA, Schnorr, Taproot, MuSig2, Nonce & Point Generation Suite (v17)")
    parser.add_argument("--sign-msg", type=str, metavar='MSG_STR', help="Sign text or a 0x-prefixed hash using the fixed demo key")
    parser.add_argument("--nonce-reuse-attack", action="store_true", help="Run an educational ECDSA nonce-reuse key-recovery demonstration")
    parser.add_argument("--pubkey-advance", type=str, metavar='PUBKEY_HEX', help="Advance a valid public point by repeatedly adding G")
    parser.add_argument("--steps", type=int, default=10, help="Number of public-point additions (1 to 1000; default: 10)")
    parser.add_argument("--wif", type=str, metavar='WIF', help="Validate WIF and derive its public key and addresses")
    parser.add_argument("--bech32-diagnose", type=str, metavar='ADDRESS', help="Check a Bech32 or Bech32m checksum")
    parser.add_argument("--walkback-trace", type=str, metavar='ADDRESS_OR_KEY', help="Parse an address/public key and report what can be known from it")
    parser.add_argument("--benchmark-mult", action="store_true", help="Benchmark generic NAF vs fixed-base multiplication and batch inversions")
    parser.add_argument("--mod-inv", nargs=2, type=lambda value: int(value, 0), metavar=('VALUE', 'MODULUS'), help="Compute VALUE inverse modulo MODULUS (decimal or 0x-prefixed)")
    parser.add_argument("--mult-neg-g", type=lambda value: int(value, 0), metavar='SCALAR', help="Compute the group inverse -(SCALAR * G)")
    parser.add_argument("--trace-scalar", "--russian-mult", dest="trace_scalar", type=lambda value: int(value, 0), metavar='SCALAR', help="Trace left-to-right double-and-add scalar multiplication of G")
    parser.add_argument("--decompress-y", type=lambda value: int(value, 0), metavar='X', help="Lift x to the even-y secp256k1 point")
    parser.add_argument("--intersection", type=lambda value: int(value, 0), metavar='X', help="Find curve point(s) at x (intersection with vertical line x=X)")
    parser.add_argument("--substitute-y-x", nargs=2, type=lambda value: int(value, 0), metavar=('X', 'Y'), help="Check whether (X,Y) satisfies y^2 = x^3 + 7 mod p")
    parser.add_argument("--curve-add", nargs=2, metavar=('PUBKEY1_HEX', 'PUBKEY2_HEX'), help="Show secant/tangent geometry and point sum for two compressed or x-only points")
    parser.add_argument("--y-equals-x", type=lambda value: int(value, 0), metavar='X', help="Evaluate y=x in the secp256k1 curve equation at x")
    parser.add_argument("--integer-mult", nargs=2, type=int, metavar=('A', 'B'), help="Trace signed integer shift-and-add multiplication")
    parser.add_argument("--mod-mult", nargs=3, type=int, metavar=('A', 'B', 'MODULUS'), help="Trace shift-and-add multiplication modulo MODULUS")
    parser.add_argument("--sha256-trace", type=str, metavar='TEXT', help="Trace the standardized forward SHA-256 compression rounds for UTF-8 text")
    parser.add_argument("--sha256-backward-ledger", type=str, metavar='DIGEST_HEX', help="Explore conditional SHA-256 backward state recovery from a 32-byte digest")
    parser.add_argument("--sha256-block", type=str, metavar='BLOCK_HEX', help="Exact 64-byte final compression block for complete backward verification")
    parser.add_argument("--sat-cnf", type=str, metavar='DIMACS_FILE', help="Solve a DIMACS CNF instance with the built-in DPLL solver")
    parser.add_argument("--sat-node-limit", type=int, default=100000, help="DPLL search node limit (default: 100000)")
    parser.add_argument("--joint-lookahead", action="store_true", help="Show the restored illustrative W63/W62 lookahead density sweep (synthetic estimates, not solver output)")
    parser.add_argument("--rsa-fermat-factor", type=lambda value: int(value, 0), metavar='N', help="Bounded Fermat factor search for an odd RSA modulus (decimal or 0x-prefixed)")
    parser.add_argument("--rsa-verify-factors", nargs=3, type=lambda value: int(value, 0), metavar=('N', 'P', 'Q'), help="Verify candidate RSA factors and public-exponent compatibility")
    parser.add_argument("--fermat-steps", type=int, default=100000, help="Maximum Fermat search iterations (default: 100000)")
    parser.add_argument("--rsa-keygen", type=int, metavar='BITS', help="Generate RSA parameters (2048 to 4096 bits) and display them")
    parser.add_argument("--rsa-demo", nargs='?', type=int, const=2048, metavar='BITS', help="Run ephemeral RSA-OAEP encryption and RSA-PSS signature demo")
    parser.add_argument("--rsa-info", action="store_true", help="Report information about --rsa-n and --rsa-e")
    parser.add_argument("--rsa-encrypt", type=str, metavar='TEXT', help="Encrypt UTF-8 text with RSA-OAEP/SHA-256")
    parser.add_argument("--rsa-decrypt", type=str, metavar='CIPHERTEXT_HEX', help="Decrypt hex ciphertext with RSA-OAEP/SHA-256")
    parser.add_argument("--rsa-sign", type=str, metavar='TEXT', help="Sign UTF-8 text with RSA-PSS/SHA-256")
    parser.add_argument("--rsa-verify", nargs=2, metavar=('TEXT', 'SIGNATURE_HEX'), help="Verify an RSA-PSS/SHA-256 signature")
    parser.add_argument("--rsa-n", type=str, metavar='MODULUS_HEX', help="RSA modulus for RSA operations")
    parser.add_argument("--rsa-e", type=int, default=65537, metavar='EXPONENT', help="RSA public exponent (default 65537)")
    parser.add_argument("--rsa-d", type=str, metavar='PRIVATE_EXPONENT_HEX', help="RSA private exponent for decrypt/sign")
    parser.add_argument("--musig2-aggregate", nargs='+', metavar='PUBKEY_HEX', help="Aggregate multiple Schnorr public keys into a joint key P_agg")
    parser.add_argument("--taproot-tweak", nargs=1, metavar='PUBKEY_X_HEX', help="Compute Taproot output key Q = P + t*G")
    parser.add_argument("--ec-prng", type=str, metavar='SEED_STR', help="Generate deterministic demonstration points (not a secure PRNG)")
    parser.add_argument("--rfc6979-trace", type=str, metavar='MSG_STR', help="Trace RFC 6979 deterministic nonce derivation")
    parser.add_argument("--schnorr-trace", type=bip340_message_arg, metavar='MSG_32_BYTES', help="Trace BIP-340 using an exactly 32-byte UTF-8 message")
    parser.add_argument("--aux-rand", type=bytes.fromhex, metavar='HEX32', help="32-byte BIP-340 auxiliary randomness as 64 hex characters (default: all-zero vector setting)")
    parser.add_argument("--hash-to-curve", type=str, metavar='SEED_STR', help="Map arbitrary seed string to valid secp256k1 point")
    parser.add_argument("--verifiable-point", type=str, metavar='SEED_STR', help="Generate a deterministically derived point using a custom construction")
    parser.add_argument("--all", action="store_true", help="Run complete suite")
    
    args = parser.parse_args()

    if args.steps != 10 and not args.pubkey_advance:
        parser.error("--steps requires --pubkey-advance")
    rsa_actions = (args.rsa_keygen is not None, args.rsa_demo is not None, args.rsa_info, args.rsa_encrypt is not None, args.rsa_decrypt is not None, args.rsa_sign is not None, args.rsa_verify is not None)
    if sum(rsa_actions) > 1:
        parser.error("choose one RSA operation per invocation")
    if (args.rsa_n or args.rsa_d) and not any(rsa_actions):
        parser.error("--rsa-n and --rsa-d must be used with an RSA operation")
    if args.sha256_block and not args.sha256_backward_ledger:
        parser.error("--sha256-block requires --sha256-backward-ledger")
    if args.aux_rand is not None and len(args.aux_rand) != 32:
        parser.error("--aux-rand must encode exactly 32 bytes (64 hex characters)")
    if args.aux_rand is not None and not (args.schnorr_trace or args.all):
        parser.error("--aux-rand requires --schnorr-trace or --all")
    if not (args.sign_msg or args.nonce_reuse_attack or args.pubkey_advance or args.wif or args.bech32_diagnose or args.walkback_trace or args.benchmark_mult or args.mod_inv or args.mult_neg_g is not None or args.trace_scalar is not None or args.decompress_y is not None or args.intersection is not None or args.substitute_y_x or args.curve_add or args.y_equals_x is not None or args.integer_mult or args.mod_mult or args.sha256_trace is not None or args.sha256_backward_ledger is not None or args.joint_lookahead or args.sat_cnf or args.rsa_fermat_factor is not None or args.rsa_verify_factors or any(rsa_actions) or args.musig2_aggregate or args.taproot_tweak or args.ec_prng or args.rfc6979_trace or args.schnorr_trace or args.hash_to_curve or args.verifiable_point or args.all):
        parser.print_help()
        return

    if args.sat_node_limit < 1:
        parser.error("--sat-node-limit must be positive")
    if args.sat_cnf:
        try:
            with open(args.sat_cnf, "r", encoding="utf-8") as cnf_file:
                variable_count, clauses = parse_dimacs_cnf(cnf_file.read())
            sat_result = solve_cnf(clauses, variable_count, args.sat_node_limit)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(f"[DPLL SAT] {sat_result['status']} variables={sat_result['variables']} clauses={sat_result['clauses']} decisions={sat_result['decisions']} propagations={sat_result['propagations']} nodes={sat_result['nodes']}")
        if sat_result["model"] is not None:
            print("    Model:", " ".join(f"{v if bit else -v}" for v,bit in sorted(sat_result["model"].items())), "0")
        return

    print("=" * 80)
    print("UNIFIED CRYPTANALYTIC, DIAGNOSTIC, MULTIPLICATIVE, GEOMETRY, WALKBACK, WIF, SCHNORR & NONCE SUITE (v17)")
    print("=" * 80)

    try:
        if args.mod_inv:
            value, modulus = args.mod_inv
            inv = modular_inverse_report(value, modulus)
            print(f"\n[Modular Inverse] {inv['value']}^(-1) mod {inv['modulus']} = {inv['inverse']} (check={inv['check']})")
        if args.mult_neg_g is not None:
            scalar = args.mult_neg_g
            point = scalar_mult_g_fast(scalar)
            negated = (0, 0) if point == (0, 0) else point_negate(point)
            print(f"\n[Group Inverse] -({scalar} * G) = {('point at infinity' if negated == (0, 0) else f'({negated[0]:064x}, {negated[1]:064x})')}")
        if args.trace_scalar is not None:
            trace = scalar_multiplication_trace(args.trace_scalar)
            print(f"\n[Scalar Trace] k={trace['scalar']} bits={trace['bit_length']} hamming_weight={trace['hamming_weight']}")
            for row in trace['steps']:
                print(f"    bit {row['bit_index']:>3}: {row['bit']} | double, {'add G' if row['added_point'] else 'no add'}")
            result = trace['result']
            print(f"    Result: {'point at infinity' if result == (0, 0) else f'({result[0]:064x}, {result[1]:064x})'}")
        if args.decompress_y is not None:
            x = args.decompress_y
            y = curve_y_roots(x)[0]
            print(f"\n[Point Lift] x=0x{x:064x} -> even y=0x{y:064x}")
        if args.intersection is not None:
            x = args.intersection
            roots = curve_y_roots(x)
            print(f"\n[Curve Intersection] vertical line x=0x{x:064x}: {len(roots)} point(s)")
            for y in roots:
                print(f"    (0x{x:064x}, 0x{y:064x})")
        if args.substitute_y_x:
            x, y = args.substitute_y_x
            valid = is_on_curve((x, y))
            print(f"\n[Curve Substitution] ({x}, {y}) is {'on' if valid else 'not on'} secp256k1")
        if args.curve_add:
            point1, point2 = (parse_pubkey(key) for key in args.curve_add)
            geom = curve_add_geometry(point1, point2)
            fmt_point = lambda pt: "point at infinity" if pt == (0, 0) else f"(0x{pt[0]:064x}, 0x{pt[1]:064x})"
            slope_text = "undefined" if geom["slope"] is None else f"0x{geom['slope']:064x}"
            print("\n[Curve Addition Geometry]")
            print(f"    Slope lambda         : {slope_text}")
            print(f"    Third intersection   : {fmt_point(geom['third_intersection'])}")
            print(f"    Group sum P1 + P2    : {fmt_point(geom['sum'])}")
        if args.y_equals_x is not None:
            report = y_equals_x_report(args.y_equals_x)
            print(f"\n[y=x substitution] residual = 0x{report['residual']:064x}; curve point: {report['is_curve_point']}")
        if args.integer_mult:
            result = russian_integer_multiply(*args.integer_mult)
            print(f"\n[Integer Shift-and-Add] {args.integer_mult[0]} * {args.integer_mult[1]} = {result['product']}")
            for index, row in enumerate(result['steps']):
                print(f"    bit {index:>3}: multiplier={row['multiplier']} bit={row['bit']} partial_sum={row['partial_sum']}")
        if args.mod_mult:
            a, b, modulus = args.mod_mult
            result = russian_modular_multiply(a, b, modulus)
            print(f"\n[Modular Shift-and-Add] ({a} * {b}) mod {modulus} = {result['result']} (verified={result['verified']})")
            for index, row in enumerate(result['steps']):
                print(f"    bit {index:>3}: multiplier={row['multiplier']} bit={row['bit']} residue={row['residue']}")
        if args.sha256_trace is not None:
            result = sha256_compression_trace(args.sha256_trace.encode('utf-8'))
            print(f"\n[SHA-256 Forward Compression Trace] digest={result['digest_hex']} verified={result['matches_hashlib']}")
            for block in result['padded_blocks']:
                print(f"    Block {block['block_index']} input state : {' '.join(block['input_state'])}")
                for round_index, state in enumerate(block['round_states']):
                    print(f"      Round {round_index:02}: {' '.join(state)}")
                print(f"    Block {block['block_index']} output state: {' '.join(block['output_state'])}")
        if args.sha256_backward_ledger is not None:
            ledger = sha256_backward_ledger(args.sha256_backward_ledger, args.sha256_block)
            print("\n[SHA-256 Backward Ledger]")
            print(f"    Assumption            : {ledger['assumption']}")
            print(f"    Final working state   : {' '.join(ledger['final_working_state'])}")
            print(f"    Fully reversed        : {ledger['fully_reversed']}")
            print(f"    Boundary              : {ledger['boundary']}")
            if ledger['fully_reversed']:
                print(f"    Recovered initial     : {' '.join(ledger['recovered_initial_state'])}")
                print(f"    Matches standard IV   : {ledger['matches_standard_iv']}")
            else:
                for name, value in ledger['last_round_recovered_state'].items():
                    print(f"    {name:22}: {value}")
            for name, value in ledger['state_classification'].items():
                print(f"    Classification {name:20}: {value}")
        if args.joint_lookahead:
            print("\n[W63/W62 Joint Lookahead Density Sweep]")
            print("    Synthetic planning estimates only; this does not run SAT or CNF solving.")
            for row in run_extended_joint_lookahead_sweep():
                print(f"    depth={row['cube_depth_bits']:>2} vars={row['remaining_vars']:>3} clauses={row['remaining_clauses']:>3} density={row['clause_density_alpha']:.4f} illustrative-propagation={row['illustrative_unit_propagation_rate_pct']:.1f}%")
        if args.rsa_fermat_factor is not None:
            factor_result = fermat_factor(args.rsa_fermat_factor, args.fermat_steps)
            if factor_result['found']:
                print(f"\n[Bounded Fermat Search] factors found in {factor_result['steps']} step(s):")
                print(f"    p = {factor_result['p']}\n    q = {factor_result['q']}")
            else:
                print(f"\n[Bounded Fermat Search] no factors found within {factor_result['steps']} step(s)")
        if args.rsa_verify_factors:
            n, p, q = args.rsa_verify_factors
            report = rsa_factor_candidate_report(n, p, q, args.rsa_e)
            print("\n[RSA Factor Candidate Check]")
            for name, value in report.items():
                print(f"    {name:32}: {value}")
    except (ValueError, OverflowError) as exc:
        parser.error(str(exc))

    try:
        rsa_n = int(args.rsa_n.removeprefix("0x"), 16) if args.rsa_n else None
        rsa_d = int(args.rsa_d.removeprefix("0x"), 16) if args.rsa_d else None
        if args.rsa_keygen is not None:
            generated = rsa_generate_keypair(args.rsa_keygen)
            print("\n[RSA] Generated educational RSA key (private values shown because --rsa-keygen was explicit):")
            for name in ("n", "e", "d", "p", "q"):
                print(f"    {name:>2} = 0x{generated[name]:x}")
        elif args.rsa_demo is not None:
            result = rsa_demo(args.rsa_demo)
            print("\n[RSA] OAEP/PSS demonstration (ephemeral key; private values not printed):")
            print(f"    Modulus size          : {result['key_info']['modulus_bits']} bits")
            print(f"    OAEP decrypt matches  : {result['decrypt_matches']}")
            print(f"    PSS signature verifies: {result['signature_verified']}")
        elif args.rsa_info:
            if rsa_n is None:
                parser.error("--rsa-info requires --rsa-n")
            info = rsa_key_info(rsa_n, args.rsa_e, rsa_d)
            print("\n[RSA] Public-key analysis:")
            for name, value in info.items():
                print(f"    {name:32}: {value}")
        elif args.rsa_encrypt is not None:
            if rsa_n is None:
                parser.error("--rsa-encrypt requires --rsa-n")
            ciphertext = rsa_oaep_encrypt(args.rsa_encrypt.encode('utf-8'), rsa_n, args.rsa_e)
            print(f"\n[RSA] OAEP ciphertext hex: {ciphertext.hex()}")
        elif args.rsa_decrypt is not None:
            if rsa_n is None or rsa_d is None:
                parser.error("--rsa-decrypt requires --rsa-n and --rsa-d")
            plaintext = rsa_oaep_decrypt(bytes.fromhex(args.rsa_decrypt), rsa_n, rsa_d)
            try:
                print(f"\n[RSA] OAEP plaintext: {plaintext.decode('utf-8')}")
            except UnicodeDecodeError:
                print(f"\n[RSA] OAEP plaintext hex: {plaintext.hex()}")
        elif args.rsa_sign is not None:
            if rsa_n is None or rsa_d is None:
                parser.error("--rsa-sign requires --rsa-n and --rsa-d")
            signature = rsa_pss_sign(args.rsa_sign.encode('utf-8'), rsa_n, rsa_d)
            print(f"\n[RSA] PSS signature hex: {signature.hex()}")
        elif args.rsa_verify is not None:
            if rsa_n is None:
                parser.error("--rsa-verify requires --rsa-n")
            message, signature_hex = args.rsa_verify
            verified = rsa_pss_verify(message.encode('utf-8'), bytes.fromhex(signature_hex), rsa_n, args.rsa_e)
            print(f"\n[RSA] PSS signature valid: {verified}")
    except (ValueError, OverflowError) as exc:
        parser.error(str(exc))

    demo_privkey = 0x01f12490f2ab49919eb91164f8b92e50b0eca5821a99797583508fd5e22108fb

    if args.sign_msg:
        signed = ecdsa_sign_and_verify_trace(demo_privkey, args.sign_msg)
        print("\n[0] ECDSA Custom Message Demo (fixed demo key):")
        print(f"    Public Key            : {signed['pubkey_hex']}")
        print(f"    Message Hash z        : {signed['hash_z_hex']}")
        print(f"    Signature r           : {signed['sig_r_hex']}")
        print(f"    Signature s           : {signed['sig_s_hex']}")
        print(f"    Low-S normalized      : {signed['low_s_normalized']}")
        print(f"    Verification          : {signed['verified']}")

    if args.pubkey_advance or args.all:
        demo_pubkey = compress_pubkey(scalar_mult_g_fast(demo_privkey)).hex()
        start_key = args.pubkey_advance if args.pubkey_advance else demo_pubkey
        advance = advance_public_key(start_key, args.steps if args.pubkey_advance else 10)
        print("\n[0a] Forward Public-Point Walk (Q_i = Q_(i-1) + G):")
        print(f"    Starting Public Key   : {advance['start_pubkey_hex']}")
        print(f"    Steps                 : {len(advance['steps'])}")
        for item in advance['steps']:
            key = item['compressed_pubkey_hex'] or "point at infinity"
            print(f"    Step {item['index']:>4}               : {key}")

    if args.wif or args.all:
        demo_wif = "KwHV8WDsBUuXPymuan5TQN82tPyRWZ68vb14ww8p9FFCw6a17xkR"
        decoded = decode_wif(args.wif if args.wif else demo_wif)
        print("\n[0c] WIF Forward Derivation:")
        print(f"    Network               : {decoded['network']}")
        print(f"    Private Scalar        : {decoded['private_key_hex'] if args.wif else '[redacted demo key]'}")
        print(f"    Public Key            : {decoded['public_key_hex']}")
        print(f"    Hash160               : {decoded['hash160_hex']}")
        print(f"    Legacy P2PKH          : {decoded['legacy_p2pkh']}")
        print(f"    Native SegWit         : {decoded['native_segwit'] or 'unavailable for uncompressed keys'}")

    if args.bech32_diagnose or args.all:
        address = args.bech32_diagnose if args.bech32_diagnose else "bc1q956d8j8ypxvk3aewnyrxx4u0dqyxf6a7exsprn"
        diag = bech32_polymod_diagnose(address)
        print("\n[0d] Bech32 Checksum Diagnosis:")
        print(f"    Address               : {diag['address']}")
        print(f"    HRP                   : {diag['hrp']}")
        print(f"    Checksum variant      : {diag['checksum_variant']}")
        print(f"    Polymod residual      : {diag['polymod_residual']}")
        print(f"    Valid checksum        : {diag['valid_checksum']}")

    if args.walkback_trace or args.all:
        target = args.walkback_trace if args.walkback_trace else "bc1q956d8j8ypxvk3aewnyrxx4u0dqyxf6a7exsprn"
        try:
            trace = walkback_trace(target)
        except ValueError as exc:
            parser.error(str(exc))
        print("\n[0f] Address/Public-Key Walkback:")
        print(f"    Input                 : {trace['input']}")
        print(f"    Parsed as             : {trace['type']}")
        if trace.get('hash160_hex'):
            print(f"    HASH160               : {trace['hash160_hex']}")
        if trace.get('witness_program_hex'):
            print(f"    Witness program       : {trace['witness_program_hex']}")
        if trace.get('public_key_hex'):
            print(f"    Public key            : {trace['public_key_hex']}")
        print(f"    Private key recovery  : {trace['private_key_recoverable']}")
        print(f"    Limit                 : {trace['limit']}")
        print("    Reverse layers:")
        for layer in trace["layers"]:
            print(f"      {layer['stage']} [{layer['status']}]")
            print(f"        {layer['data']}")

    if args.benchmark_mult or args.all:
        bench = run_performance_benchmark()
        print("\n[0e] Performance Benchmark (points are checked for equality):")
        print(f"    Trials                : {bench['trials']}")
        print(f"    Generic NAF           : {bench['generic_naf_seconds']:.4f}s")
        print(f"    Fixed-base            : {bench['fixed_base_seconds']:.4f}s ({bench['fixed_base_speedup_percent']:.1f}% faster)")
        print(f"    Individual inversions : {bench['individual_inversions_seconds']:.4f}s")
        print(f"    Batch inversions      : {bench['batch_inversions_seconds']:.4f}s ({bench['batch_inversion_speedup_percent']:.1f}% faster)")

    if args.nonce_reuse_attack or args.all:
        attack = ecdsa_nonce_reuse_attack_trace(
            demo_privkey,
            0x9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef,
        )
        print("\n[0b] ECDSA Nonce-Reuse Demonstration:")
        print(f"    Shared r              : {attack['shared_r_hex']}")
        print(f"    Nonce recovered       : {attack['nonce_recovered']}")
        print(f"    Private key recovered : {attack['private_key_recovered']}")

    # CLI Command 1: RFC 6979 Nonce
    if args.rfc6979_trace or args.all:
        msg_str = args.rfc6979_trace if args.rfc6979_trace else "RFC 6979 Deterministic Nonce Test Payload"
        priv_d = demo_privkey
        res = rfc6979_trace(priv_d, msg_str)
        print("\n[1] RFC 6979 Deterministic Nonce Derivation Engine:")
        print("    Private Key d         : [redacted demo key]")
        print(f"    Message Payload       : \"{res['msg_input']}\"")
        print(f"    Message SHA-256 Hash z: {res['hash_z_hex']}")
        print(f"    Deterministic Nonce k : {res['rfc6979_k_hex']}")
        print(f"    Ephemeral Point R     : (0x{res['ephemeral_R_affine'][0]:064x}, 0x{res['ephemeral_R_affine'][1]:064x})")
        print("    Property              : Deterministic for this key and message hash.")

    # CLI Command 2: BIP-340 Schnorr Trace
    if args.schnorr_trace or args.all:
        msg_str = args.schnorr_trace if args.schnorr_trace else "Taproot payload".ljust(32, " ")
        priv_d = demo_privkey
        res = schnorr_bip340_sign_and_verify_trace(
            priv_d, msg_str, aux_rand=args.aux_rand or b"\x00" * 32
        )
        print("\n[2] BIP-340 Schnorr Signature & Taproot Verification Trace:")
        print("    Private Key d         : [redacted demo key]")
        print(f"    x-Only Public Key P_x : {res['x_only_pubkey_P_hex']} (y Even: {res['P_y_even']})")
        print(f"    Deterministic Nonce k : {res['nonce_k_hex']}")
        print(f"    Ephemeral Point R_x   : {res['R_x_hex']}")
        print(f"    Challenge Hash e      : {res['challenge_e_hex']}")
        print(f"    Signature Scalar s    : {res['sig_s_hex']}")
        print(f"    s * G Affine Point    : (0x{res['sG_affine'][0]:064x}, 0x{res['sG_affine'][1]:064x})")
        print(f"    R + e*P Affine Point  : (0x{res['R_plus_eP_affine'][0]:064x}, 0x{res['R_plus_eP_affine'][1]:064x})")
        print(f"    Verification Status   : Verified -> {res['verified']}")
        print("    Verification Property : s * G == R + e * P (Zero scalar inversions required)")

    # CLI Command 3: Hash-to-Curve
    if args.hash_to_curve or args.all:
        seed_str = args.hash_to_curve if args.hash_to_curve else "SESPake_curve_point_seed"
        h2c = hash_to_curve_try_and_increment(seed_str)
        print("\n[3] Hash-to-Curve Try-and-Increment Engine (secp256k1):")
        print(f"    Seed String Input     : \"{h2c['seed']}\"")
        print(f"    Tries Until Solution  : {h2c['tries']}")
        print(f"    Derived Point P_x     : {h2c['point_x_hex']}")
        print(f"    Derived Point P_y     : {h2c['point_y_hex']}")
        print(f"    Curve Verification    : y^2 == x^3 + 7 mod P -> {h2c['on_curve']}")

    # CLI Command 4: Verifiable Point
    if args.verifiable_point or args.all:
        seed_str = args.verifiable_point if args.verifiable_point else "ISO_IEC_15946_5_seed"
        vpt = verifiable_pseudorandom_point(seed_str)
        print("\n[4] Deterministically Derived Point Generator:")
        print(f"    Seed String Input     : \"{vpt['seed']}\"")
        print(f"    Derived Scalar c      : {vpt['derived_scalar_c_hex']}")
        print(f"    Derived Point Q_x     : {vpt['verifiable_point_Q_x_hex']}")
        print(f"    Derived Point Q_y     : {vpt['verifiable_point_Q_y_hex']}")
        print(f"    Derivation Note       : {vpt['trust_property']}")

    # CLI Command 5: MuSig2 Key Aggregation
    if args.musig2_aggregate or args.all:
        keys = args.musig2_aggregate if args.musig2_aggregate else [
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "02038fbdd86e5f2a1781fbe8a7476d14af8544fdd5a737be5fbeb11cc912c026a5"
        ]
        musig = musig2_aggregate_keys(keys)
        print("\n[5] MuSig2 Multi-Party Key Aggregation Engine:")
        print(f"    Aggregated Keys Count : {musig['input_pubkeys_count']}")
        print(f"    Key Coefficients a_i  : {musig['key_coefficients_a_i']}")
        print(f"    Aggregated Point P_agg: ({musig['aggregated_point_x_hex']}, {musig['aggregated_point_y_hex']})")

    # CLI Command 6: Taproot Tweak
    if args.taproot_tweak or args.all:
        pk_x = args.taproot_tweak[0] if args.taproot_tweak else "0x038fbdd86e5f2a1781fbe8a7476d14af8544fdd5a737be5fbeb11cc912c026a5"
        tweak = taproot_tweak_pubkey(pk_x)
        print("\n[6] Taproot Tweak Engine (Q = P + t*G):")
        print(f"    Internal PubKey P_x   : {tweak['internal_pubkey_x_hex']}")
        print(f"    Taproot Tweak t       : {tweak['taproot_tweak_t_hex']}")
        print(f"    Output Taproot Key Q_x: {tweak['output_taproot_pubkey_x_hex']}")

    # CLI Command 7: Long Period PRNG
    if args.ec_prng or args.all:
        seed_str = args.ec_prng if args.ec_prng else "high_dim_simulation_seed"
        prng = long_period_ec_prng_generator(seed_str)
        print("\n[7] Long-Period Elliptic Curve PRNG Vector Generator:")
        print(f"    Seed String Input     : \"{prng['seed']}\"")
        print(f"    Security Note         : {prng['security_note']}")
        print("    Generated PRNG Vectors:")
        for idx, vec in enumerate(prng['generated_pseudorandom_vectors']):
            print(f"      Dim {idx+1} | x: {vec['coord_x_hex'][:18]}... | y: {vec['coord_y_hex'][:18]}...")

    print("=" * 80)

if __name__ == "__main__":
    main()
