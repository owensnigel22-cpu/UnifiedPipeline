# Fuzzing KeyLab's parsers

KeyLab fuzzes its untrusted-input parsers with coverage-guided
[Atheris](https://github.com/google/atheris) (libFuzzer for Python). This is
**test/CI tooling only** — the `fuzz/` tree is not part of the importable
`keylab` library, is excluded from the sdist/wheel, and adds no runtime
dependency. It does not change any production behaviour and does not touch
`SECURITY.md`.

## Targets

Six byte/string input surfaces, all of which already raise typed errors on bad
input:

| Target | Entry point |
|---|---|
| `psbt` | `keylab.psbt.parse` |
| `transaction` | `keylab.encoding.transaction.parse_transaction` |
| `bech32` | `keylab.encoding.bech32.decode` / `decode_segwit_address` |
| `base58` | `keylab.encoding.base58.b58decode` / `check_decode` |
| `wif` | `keylab.encoding.wif.decode` |
| `mnemonic` | `keylab.mnemonic.mnemonic_to_entropy` / `is_valid_mnemonic` |

The shared, deterministic target bodies live in `fuzz/targets.py` (one source of
truth). Each applies a cheap "grammar-lite" prefix filter (e.g. the `psbt\xff`
magic, a bech32 `1` separator, a WIF version-char, a real first mnemonic word) so
the fuzzer spends its budget reaching deep parser states instead of the shallow
reject path, and swallows only each parser's **documented** exception
(`ValueError` / `PsbtError`); any other exception propagates as a finding.

## Platform

Atheris is Linux-only. **Fuzzing runs on Linux (CI, Python 3.12)**; the pinned
`atheris==3.1.0` ships a cp312 manylinux wheel. On Windows/macOS or anywhere
Atheris is absent, you cannot run the coverage-guided campaign, but the same
target bodies are exercised over the seed corpora by the cross-platform test
`tests/test_corpus_smoke.py` (`test_corpus_smoke`, **not** fuzzing — it is not
counted as fuzz coverage).

## Running locally (Linux)

```sh
python -m pip install -e ".[dev,fuzz]"
# one target, 30s, reproducible seed:
python scripts/run_fuzz.py bech32 --time 30 --reproducible
# all targets:
python scripts/run_fuzz.py all --time 30
```

`scripts/run_fuzz.py` seeds the corpus from the pinned vectors first, then runs
each target with `-timeout=5` (per-input; timeouts are findings),
`-rss_limit_mb=2048`, and a per-target `-max_len` (65536 for `psbt`/`transaction`,
1024 otherwise). Any crash or timeout exits non-zero.

## Seed corpora & provenance

Seeds are generated **at runtime** from the pinned official vectors in
`tests/vectors/` (`fuzz/corpus_seed.py`) plus a few near-valid literals. No new
copies of vector data are committed, so the `tests/vectors/SOURCES.json`
provenance gate is unaffected. The **PR smoke** job is generated-only and uses a
fixed libFuzzer seed, so it is reproducible. The **nightly** job additionally
caches and uploads its evolved corpus as a CI artifact to compound coverage;
those corpus artifacts are *derived* data and are deliberately **not** under the
`SOURCES.json` provenance gate.

## CI

- **`fuzz-smoke`** (in `ci.yml`, ubuntu, Python 3.12): on every PR/push, a short
  bounded campaign over all six targets, plus a canary check. Crashes/timeouts
  fail the job (release blockers).
- **`fuzz-nightly.yml`** (scheduled): an extended campaign with corpus
  caching/artifact upload.

## The canary

`fuzz/fuzz_canary.py` targets a deliberately out-of-bounds toy parser that lives
only in the fuzz tree (never in `src/keylab`). CI asserts the harness **catches**
it (a non-zero exit); if the canary ever passes, the harness is miswired and the
gate blocks. `tests/test_corpus_smoke.py` additionally asserts the canary is not
importable as a `keylab` submodule.

## If a campaign finds a crash

A crash or timeout is a genuine finding and a release blocker. Fix the parser (or,
only if the input is genuinely out of contract, tighten the target's documented
expected-exception set with justification) — never silence it by broadening the
caught-exception set.
