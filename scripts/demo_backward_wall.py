"""Live demonstration of backward double-and-add, its limits, and Pollard's kangaroo.

Run: python scripts/demo_backward_wall.py

Shows that point halving is exact, that each backward step has two valid branches,
that recovery enumerates 2**bit_length(k) leaves (i.e. the ECDLP, no shortcut), and
that the kangaroo is the right O(sqrt(width)) tool for a bounded interval. None of
this threatens a real 256-bit key.
"""

from __future__ import annotations

import random

from keylab.ec.secp256k1 import G, point_add_affine, point_negate_affine, scalar_mult
from keylab.recovery.backward_double_add import (
    backward_step,
    cost_table,
    point_halve,
    recover_via_backward,
)
from keylab.recovery.kangaroo import recover_via_kangaroo

RULE = "=" * 72


def _double(point):
    return point_add_affine(point, point)


def demo_halving() -> None:
    print(RULE, "\n 1. Point halving is exact: P = ((N+1)/2)*Q, so 2P = Q\n", RULE, sep="")
    for k in (1, 2, 7, 100):
        q = scalar_mult(k, G)
        half = point_halve(q)
        print(f"   halve({k}G).x = {hex(half[0])[:18]}...  2*halve == {k}G: {_double(half) == q}")
    print()


def demo_branches() -> None:
    print(RULE, "\n 2. Each backward step has two valid, indistinguishable branches\n", RULE, sep="")
    q = scalar_mult(10, G)
    q_minus_g = point_add_affine(q, point_negate_affine(G))
    half_zero, half_one = backward_step(q)
    print("   Q = 10G")
    print(f"   bit 0: halve(Q).x   = {hex(half_zero[0])[:18]}...  2*h0 == Q:     {_double(half_zero) == q}")
    print(f"   bit 1: halve(Q-G).x = {hex(half_one[0])[:18]}...  2*h1 == Q - G: {_double(half_one) == q_minus_g}")
    print()


def demo_recovery() -> None:
    print(RULE, "\n 3. Recovery enumerates up to 2**depth leaves (this is brute force)\n", RULE, sep="")
    rng = random.Random(0xCAFE)
    for depth in (6, 8, 10, 12):
        k = rng.randrange(1, 1 << depth)
        report = recover_via_backward(scalar_mult(k, G), max_depth=depth)
        print(f"   depth={depth:>2}  k={k:<5}  2^depth={1 << depth:>5}  "
              f"leaves={report['leaves_explored']:>5}  time={report['time_sec'] * 1000:>8.1f}ms  "
              f"found={report['found']}")
    print()


def demo_kangaroo() -> None:
    print(RULE, "\n 4. Bounded interval: Pollard's kangaroo is O(sqrt(width))\n", RULE, sep="")
    k = 0xBEEF_1234
    for half_width in (2_000, 20_000):
        report = recover_via_kangaroo(scalar_mult(k, G), k - half_width, k + half_width)
        print(f"   width={2 * half_width:>7}  found={report['found']}  "
              f"k matches: {report['k'] == k}  time={report['time_sec'] * 1000:>7.1f}ms")
    print()


def demo_wall() -> None:
    print(RULE, "\n 5. The wall: no shortcut exists for reversing double-and-add\n", RULE, sep="")
    for bits, leaves, label in cost_table():
        shown = f"{leaves:,}" if bits <= 32 else f"2^{bits}"
        print(f"   k={bits:>3} bits  leaves={shown:>26}  {label}")
    print("\n   A 256-bit key is 2^256 leaves (ECDLP). Even the kangaroo needs 2^128.")


if __name__ == "__main__":
    demo_halving()
    demo_branches()
    demo_recovery()
    demo_kangaroo()
    demo_wall()
