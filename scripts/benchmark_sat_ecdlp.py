"""Measure the ceiling of the SAT bounded-range ECDLP encoder on secp256k1 -- safely.

RESULT (recorded in SEC_STATE_JOURNAL.md): the full 256-bit field encoding makes
~8M clauses per point-doubling step and the SAT solver does not terminate even at
1 step. This is a clause/memory blow-up and a dead end.

Safety (this experiment has crashed hosts): every build and solve runs in a
SUBPROCESS under a hard memory cap (a Windows Job Object / POSIX RLIMIT_AS via
scripts/run_capped.py) and a wall-clock timeout, and the CNF is STREAMED to a
DIMACS file as it is generated (never an 8M-tuple list in RAM). A breach is a
clean kill, never a host crash.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_capped import run_capped

from keylab.ec.secp256k1 import G, P, scalar_mult
from keylab.research.ecdlp.sat_encoding import encode_bounded_ecdlp
from keylab.sat.cnf import CNF

_WIDTH = 256


class _ClauseSink:
    """List-like stand-in for CNF.clauses that writes each clause to disk, keeping only a count."""

    def __init__(self, path: str) -> None:
        self._fh = open(path, "w", encoding="ascii", buffering=1 << 20)  # noqa: SIM115 (lives for the sink's lifetime; closed in close())
        self._count = 0

    def append(self, clause: tuple[int, ...]) -> None:
        self._fh.write(" ".join(map(str, clause)))
        self._fh.write(" 0\n")
        self._count += 1

    def extend(self, clauses) -> None:
        write = self._fh.write
        for clause in clauses:
            write(" ".join(map(str, clause)))
            write(" 0\n")
            self._count += 1

    def __len__(self) -> int:
        return self._count

    def __iter__(self):
        return iter(())

    def close(self) -> None:
        self._fh.close()


class StreamingCNF(CNF):
    """A CNF whose clauses stream to a temp file instead of accumulating in memory."""

    def __init__(self, clause_path: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.clauses = _ClauseSink(clause_path)  # type: ignore[assignment]


def _instance(steps: int):
    d = 1 << (steps - 1)                       # single top bit -> one non-exceptional add
    lower, upper, k = 1000, 1000 + d, 1000 + d
    base = scalar_mult(lower, G)
    top = scalar_mult(1 << (steps - 1), G)
    assert base is not None and top is not None and base[0] != top[0], "exceptional; bump lower"
    dpts = [scalar_mult(1 << i, G) for i in range(steps)]
    return lower, upper, k, base, dpts, scalar_mult(k, G)


def build_one(steps: int, out_path: str) -> tuple[int, int]:
    """Stream the DIMACS for one `steps`-doubling instance to `out_path`; return (vars, clauses)."""

    lower, upper, _, base, dpts, target = _instance(steps)
    clause_tmp = out_path + ".clauses"
    scnf = StreamingCNF(clause_tmp)
    inst = encode_bounded_ecdlp(p=P, width=_WIDTH, base_point=base, doubling_points=dpts,
                                target=target, lower=lower, upper=upper, cnf=scnf)
    variables = scnf.variable_count
    clauses = len(scnf.clauses)
    scnf.clauses.close()  # type: ignore[union-attr]
    # prepend the DIMACS header, then the streamed clause body
    with open(out_path, "w", encoding="ascii", buffering=1 << 20) as out, \
            open(clause_tmp, encoding="ascii") as body:
        out.write(f"p cnf {variables} {clauses}\n")
        out.writelines(iter(lambda: body.read(1 << 20), ""))
    Path(clause_tmp).unlink(missing_ok=True)
    _ = inst  # the instance's difference_bits/recover_k are used by callers that solve
    return variables, clauses


def _find_solver():
    import shutil
    for name in ("kissat", "cadical", "cryptominisat5", "cryptominisat", "minisat"):
        path = shutil.which(name)
        if path:
            return path
    return None


def orchestrate(steps_list, cap_bytes, build_timeout, solve_timeout, tmp_dir):
    solver = _find_solver()
    print(f"solver={solver} cap={cap_bytes >> 20}MiB build_timeout={build_timeout}s solve_timeout={solve_timeout}s")
    print(f"{'steps':>5} {'variables':>13} {'clauses':>13} {'build':>14} {'solve':>16}")
    for steps in steps_list:
        dimacs = str(Path(tmp_dir) / f"ecdlp_s{steps}.cnf")
        br = run_capped([sys.executable, "-I", __file__, "--build", str(steps), dimacs],
                        mem_bytes=cap_bytes, timeout=build_timeout)
        if br.status != "ok":
            print(f"{steps:>5} {'-':>13} {'-':>13} {'BUILD '+br.status.upper():>14} {'-':>16}")
            print(f"-- build failed cleanly ({br.status}); not a host crash. Stopping.")
            break
        counts = dict(tok.split("=") for tok in br.stdout.split() if "=" in tok)
        variables, clauses = counts.get("VARS", "?"), counts.get("CLAUSES", "?")
        solve_desc = "not-attempted"
        if solver is not None:
            sr = run_capped([solver, dimacs], mem_bytes=cap_bytes, timeout=solve_timeout)
            if sr.status == "timeout":
                solve_desc = "TIMEOUT"
            elif sr.status == "memory":
                solve_desc = "MEM-KILLED"
            else:
                line = next((ln for ln in sr.stdout.splitlines() if ln.startswith("s ")), "")
                solve_desc = line[2:].strip() or "DONE"
        print(f"{steps:>5} {variables:>13} {clauses:>13} {'OK':>14} {solve_desc:>16}")
        sys.stdout.flush()
        Path(dimacs).unlink(missing_ok=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="SAT ECDLP ceiling, memory-safe by construction.")
    ap.add_argument("--build", nargs=2, metavar=("STEPS", "OUT"),
                    help="internal: stream one instance's DIMACS to OUT and print counts")
    ap.add_argument("--steps", type=int, nargs="+", default=[1, 2])
    ap.add_argument("--cap-mib", type=int, default=700)
    ap.add_argument("--build-timeout", type=float, default=240.0)
    ap.add_argument("--solve-timeout", type=float, default=90.0)
    ap.add_argument("--tmp", type=str, default=".")
    args = ap.parse_args()

    if args.build:
        steps, out = int(args.build[0]), args.build[1]
        v, c = build_one(steps, out)
        print(f"VARS={v} CLAUSES={c}")
    else:
        orchestrate(args.steps, args.cap_mib << 20, args.build_timeout, args.solve_timeout, args.tmp)
