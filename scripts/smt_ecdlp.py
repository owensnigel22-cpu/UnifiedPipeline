"""Word-level SMT (QF_BV) encoding of the bounded-range ECDLP, as a Part-2 alternative to CNF.

Re-expresses the same field operations as bit-vector arithmetic so an SMT solver
(z3) reasons about modular add/mul/reduce as structured operations rather than
flat CNF clauses. Validates on a toy curve (solver recovers the known k), then
attempts the real 256-bit secp256k1 1-doubling instance under z3's own memory and
time limits (wrapped by scripts/run_capped.py for a hard OS cap).
"""

from __future__ import annotations

import argparse
import sys
import time

import z3

from keylab.ec.secp256k1 import G, P, scalar_mult


def _mk(p: int, width: int):
    pbv = z3.BitVecVal(p, width)
    pbv1 = z3.BitVecVal(p, width + 1)
    pbv2 = z3.BitVecVal(p, 2 * width)

    def modsub(a, b):
        return z3.If(z3.UGE(a, b), a - b, a - b + pbv)

    def modadd(a, b):
        s = z3.ZeroExt(1, a) + z3.ZeroExt(1, b)
        return z3.Extract(width - 1, 0, z3.If(z3.UGE(s, pbv1), s - pbv1, s))

    def modmul(a, b):
        prod = z3.ZeroExt(width, a) * z3.ZeroExt(width, b)  # 2*width bits
        return z3.Extract(width - 1, 0, z3.URem(prod, pbv2))

    return modsub, modadd, modmul, pbv


def build(solver, steps, p, width, base, dpts, target, lower, upper):
    modsub, _modadd, modmul, _ = _mk(p, width)  # modadd unused: the add law needs only sub/mul here
    span = upper - lower
    bits = [z3.Bool(f"d{i}") for i in range(steps)]
    # d = sum d_i 2^i, constrain d <= span
    d_expr = z3.BitVecVal(0, max(steps + 1, 8))
    for i, bit in enumerate(bits):
        d_expr = d_expr + z3.If(bit, z3.BitVecVal(1 << i, d_expr.size()), z3.BitVecVal(0, d_expr.size()))
    solver.add(z3.ULE(d_expr, z3.BitVecVal(span, d_expr.size())))

    acc_x = z3.BitVecVal(base[0], width)
    acc_y = z3.BitVecVal(base[1], width)
    for i in range(steps):
        x2 = z3.BitVecVal(dpts[i][0], width)
        y2 = z3.BitVecVal(dpts[i][1], width)
        dx = modsub(acc_x, x2)
        dy = modsub(acc_y, y2)
        inv = z3.BitVec(f"inv{i}", width)
        solver.add(z3.ULT(inv, z3.BitVecVal(p, width)))
        solver.add(z3.Implies(bits[i], modmul(inv, dx) == z3.BitVecVal(1, width)))  # gated
        lam = modmul(dy, inv)
        x3 = modsub(modsub(modmul(lam, lam), acc_x), x2)
        y3 = modsub(modmul(lam, modsub(acc_x, x3)), acc_y)
        acc_x = z3.If(bits[i], x3, acc_x)
        acc_y = z3.If(bits[i], y3, acc_y)

    solver.add(acc_x == z3.BitVecVal(target[0], width))
    solver.add(acc_y == z3.BitVecVal(target[1], width))
    return bits


def _recover(model, bits, lower):
    d = sum(1 << i for i, b in enumerate(bits) if z3.is_true(model[b]))
    return lower + d


def solve_toy():
    p, a, b = 1009, 2, 3

    def add(Pt, Q):
        if Pt is None:
            return Q
        if Q is None:
            return Pt
        x1, y1 = Pt
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        m = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p if Pt == Q else (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (m * m - x1 - x2) % p
        return (x3, (m * (x1 - x3) - y1) % p)

    def mul(k, Pt):
        R = None
        while k > 0:
            if k & 1:
                R = add(R, Pt)
            Pt = add(Pt, Pt)
            k >>= 1
        return R

    g = next((x, y) for x in range(p) for y in range(p) if (y * y - (x * x * x + a * x + b)) % p == 0)
    width, k, lo, hi, steps = p.bit_length(), 3, 1, 7, 3
    base, target = mul(lo, g), mul(k, g)
    dpts = [mul(1 << i, g) for i in range(steps)]
    s = z3.Solver()
    bits = build(s, steps, p, width, base, dpts, target, lo, hi)
    t0 = time.perf_counter()
    res = s.check()
    ok = res == z3.sat and _recover(s.model(), bits, lo) == k
    print(f"TOY: status={res} recovered={'k='+str(k)+' OK' if ok else 'FAIL'} ({time.perf_counter()-t0:.2f}s)")
    return ok


def solve_secp(steps, budget_s, mem_mib):
    d = 1 << (steps - 1)
    lower, upper, k = 1000, 1000 + d, 1000 + d
    base = scalar_mult(lower, G)
    dpts = [scalar_mult(1 << i, G) for i in range(steps)]
    target = scalar_mult(k, G)
    z3.set_option("memory_max_size", mem_mib)  # z3's own soft cap (MiB)
    s = z3.Solver()
    s.set("timeout", int(budget_s * 1000))
    bits = build(s, steps, P, 256, base, dpts, target, lower, upper)
    t0 = time.perf_counter()
    res = s.check()
    elapsed = time.perf_counter() - t0
    correct = None
    if res == z3.sat:
        correct = _recover(s.model(), bits, lower) == k
    print(f"SECP steps={steps}: status={res} correct={correct} elapsed={elapsed:.1f}s")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["toy", "secp"])
    ap.add_argument("--steps", type=int, default=1)
    ap.add_argument("--budget", type=float, default=90.0)
    ap.add_argument("--mem-mib", type=int, default=600)
    args = ap.parse_args()
    if args.mode == "toy":
        sys.exit(0 if solve_toy() else 1)
    solve_secp(args.steps, args.budget, args.mem_mib)
