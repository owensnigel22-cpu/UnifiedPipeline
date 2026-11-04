"""Run one or all KeyLab fuzz targets under Atheris for a bounded budget.

Usage::

    python scripts/run_fuzz.py <target|all> [--time SECONDS] [--extra "<libfuzzer flags>"]

Linux only (Atheris). Seeds the corpus from the pinned vectors first, then runs
each target's ``fuzz/fuzz_<target>.py`` as a subprocess with the agreed flags:
per-input ``-timeout=5`` (timeouts are findings), ``-rss_limit_mb=2048``, and a
per-target ``-max_len``. A non-zero exit from any target (crash or timeout) fails
the run, so CI treats findings as blockers.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "fuzz" / "corpus"
# Make the top-level `fuzz` package importable regardless of launch cwd
# (running `python scripts/run_fuzz.py` puts scripts/ on sys.path, not ROOT).
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TARGETS = ("psbt", "transaction", "bech32", "base58", "wif", "mnemonic")
MAX_LEN = {"psbt": 65536, "transaction": 65536, "bech32": 1024, "base58": 1024, "wif": 1024, "mnemonic": 1024}


def _run_one(target: str, seconds: int, reproducible: bool, extra: list[str]) -> int:
    script = ROOT / "fuzz" / f"fuzz_{target}.py"
    corpus_dir = CORPUS / target
    corpus_dir.mkdir(parents=True, exist_ok=True)
    flags = [
        f"-max_total_time={seconds}",
        "-timeout=5",
        "-rss_limit_mb=2048",
        f"-max_len={MAX_LEN[target]}",
        "-print_final_stats=1",
    ]
    if reproducible:
        flags.append("-seed=1")
    flags += extra
    cmd = [sys.executable, str(script), *flags, str(corpus_dir)]
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(ROOT), os.environ.get("PYTHONPATH", "")])}
    print(f"=== fuzz {target}: {' '.join(flags)} ===", flush=True)
    return subprocess.run(cmd, check=False, cwd=ROOT, env=env).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", help="one of the targets, or 'all'")
    parser.add_argument("--time", type=int, default=30, help="seconds per target (default 30)")
    parser.add_argument("--reproducible", action="store_true", help="use a fixed libFuzzer seed")
    parser.add_argument("--extra", default="", help="extra libFuzzer flags, space-separated")
    args = parser.parse_args(argv)

    # Seed the corpus from the pinned vectors (derived data; not committed).
    from fuzz.corpus_seed import write_corpus
    counts = write_corpus(CORPUS)
    print("seeded:", ", ".join(f"{k}={v}" for k, v in counts.items()), flush=True)

    targets = TARGETS if args.target == "all" else (args.target,)
    extra = args.extra.split() if args.extra else []
    failures = []
    for target in targets:
        if target not in TARGETS:
            parser.error(f"unknown target {target!r}; choose from {TARGETS} or 'all'")
        if _run_one(target, args.time, args.reproducible, extra) != 0:
            failures.append(target)
    if failures:
        print(f"FUZZ FINDINGS (crash/timeout) in: {', '.join(failures)}")
        return 1
    print("fuzz run clean: no crashes or timeouts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
