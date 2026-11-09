# Development Rules

These rules summarize `AGENTS.md`, `CONTRIBUTING.md`, `pyproject.toml`, `docs/TEST_STRATEGY.md`, and `docs/benchmarks.md`. The project owner retains final approval authority.

## Coding and Scope

- Correctness and input validation precede optimization. Follow existing module boundaries and avoid duplicate implementations.
- Preserve public APIs and serialized behavior unless a task is explicitly approved to change them; record compatibility impact.
- Keep research code, production-oriented support, optional integrations, and development-only tooling distinguishable. Do not delete research because it is slow or experimental.
- Use Python 3.11 or newer. Ruff is configured for a 100-character line length and Python 3.11. Mypy targets `src`; see `pyproject.toml` for the exact configuration.
- Use synthetic/public test material only. Never commit real wallet secrets.

## Testing

Before editing, identify nearby tests and the smallest discriminating validation. Add or update tests when observable behavior changes. Choose from official vectors, focused unit/regression tests, property-based tests, differential tests, fuzzing, and optional-backend tests according to risk.

From the `keylab/` repository root, the contributor guide documents `pytest` and `ruff check .` as pre-change gates. Run focused tests first, then applicable broader checks. Optional dependencies may lead to skips; report the skip reason and do not describe skipped coverage as passed. For documentation/configuration-only changes, validate links, paths, consistency, and the changed-file boundary rather than running unrelated application tests.

Every handoff reports exact commands and observed outcomes. Do not claim a test, type check, benchmark, security review, or instruction activation without direct evidence.

## Dependencies

Core required dependencies are listed under `[project].dependencies`; optional integrations belong in the established extras when appropriate. Do not install packages or alter dependency declarations without explicit project-owner approval. Record backend and version in benchmark/research outputs. Review platform support, license, maintenance cost, and optional-test behavior before proposing a new dependency.

## Documentation

Document only behavior supported by inspected source, executed tests, or raw benchmark evidence. Cite repository paths and commands where useful. Mark proposed, inferred, not-run, extrapolated, and measured statements distinctly. Update API, security, usage, changelog, and research records when a task changes those surfaces. Preserve failed and negative results with provenance.

## Review

Every task has one implementation owner and a bounded file/scope assignment in `CURRENT_TASKS.md`. Another agent may review independently. Avoid simultaneous edits to the same files. Cryptographic behavior, key handling, parsing rules, dependencies, security claims, and architectural changes require project-owner scrutiny. Integrate changes through reviewed PRs; the project owner decides merges.

## Performance Evidence

Follow `docs/benchmarks.md`: use a reproducible corpus/seed, verify correctness before timing, warm up as specified, randomize comparison order where applicable, report a robust statistic and environment/backend, and keep secret values out of output. Distinguish algorithmic estimates from executed measurements. Never add machine-dependent timing assertions to ordinary tests without an approved rationale.
