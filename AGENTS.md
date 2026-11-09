# Shared Agent Instructions

This file is the authoritative project instruction source for GitHub Copilot, Claude Code, OpenAI Codex, and other coding agents working in this repository. Read it before acting. Read `docs/coordination/PROJECT_STATUS.md`, `CURRENT_TASKS.md`, and `AGENT_HANDOFF.md` at the start of every task, then inspect the current Git branch and worktree. `CLAUDE.md` and `.github/copilot-instructions.md` point here; they must not define conflicting policies.

## Project Identity

The repository is UnifiedPipeline; its Python distribution and import package are named Keylab (`keylab`). Keylab is a research and teaching library for Bitcoin key/signature standards and cryptographic analysis. The repository contains reference cryptographic implementations, Bitcoin encodings and protocol helpers, PSBT v0 roles, SAT/hash and number-theory experiments, research code, command-line tools, benchmarks, fuzz harnesses, tests, documentation, and an optional Streamlit dashboard.

The technical objectives are correctness against published standards and vectors, understandable reference implementations, constrained and reproducible research, explicit separation of experimental from protocol code, and measurable performance comparisons. Production is a project goal only in the sense of maintainable packaging and reliable engineering; the cryptographic implementation is not production wallet or key-management software. Never imply that it is safe for real funds or independently audited.

Architectural boundaries and current capabilities are documented in `docs/architecture.md`, `SECURITY.md`, `docs/RESEARCH_SUBSYSTEM_ARCHITECTURE.md`, and `docs/IMPLEMENTATION_ROADMAP.md`. Verify those documents and source before making or repeating detailed claims.

## Engineering Standards

- Correctness comes before speed or feature breadth. Preserve standards behavior, input validation, and compatibility unless an approved task explicitly changes them.
- Develop security-consciously. Minimize secret exposure; do not log secrets; use synthetic or public fixtures; state threat models and limitations accurately.
- Prefer small, maintainable changes that respect the existing module boundaries and public APIs. Avoid duplicate implementations and unrelated refactors.
- Preserve backward compatibility by default. Identify API, serialization, CLI, and data-format impact before changing them; document any intentional incompatibility.
- Meaningful behavior changes require focused tests. Reuse project test patterns, official vectors, property tests, differential checks, and negative cases as appropriate.
- Benchmarks must be reproducible and correctness-gated. Record commands, environment/backend, seed or corpus, and measured results. Do not convert a single local timing into a general performance claim.
- Keep technical documentation synchronized with verified source and test behavior. Label proposals, hypotheses, unrun work, and measured results distinctly.
- Follow `CONTRIBUTING.md` and `pyproject.toml`: Python 3.11+, Ruff line length 100, pytest project configuration, and mypy configured for `src`. Do not change dependencies without explicit project-owner approval.

## Preserve Research

Research is part of the deliverable. Do not remove or hide experimental algorithms, alternative implementations, benchmark tools, test vectors, reproducibility scripts, research documents, or negative experimental findings merely because they are not production-ready or fast.

Clearly classify functionality as production-oriented engineering support, reference/protocol implementation, experimental, optional-backend, or development-only. The classifications describe project maturity, not a security certification. Prefer optional dependency extras for non-core integrations; do not make a research backend mandatory without owner approval. Retain failed, infeasible, and negative results with provenance and distinguish measured results from extrapolations and proposals.

## Validation and Reporting

Before editing, identify the relevant tests and validation commands. When behavior changes, add or update appropriate tests. Run the focused checks required by the change and any repository-required gates that are practical. In the handoff, state exact commands and observed results, including failures, skipped checks, and environmental limitations. Never claim a test, benchmark, audit, or instruction activation succeeded without evidence. Documentation-only changes should receive documentation/path/consistency checks; do not run unrelated application suites as a substitute.

## Security Requirements

Use `SECURITY.md` as the current project security statement. Keylab's Python cryptographic arithmetic is not constant-time or side-channel hardened; secret-dependent branches/table access and modular inversions can be variable-time. Python does not reliably erase secrets from memory. The project is not a wallet, not a consensus implementation, and is not independently audited. Optional native backends may have different properties, but their use does not certify the surrounding application or all call paths.

Do not overstate protections, attack feasibility, or production readiness. Preserve distinctions between public-input operations and secret-key operations, and between constant-time helpers such as fixed-time comparison and variable-time arithmetic. Changes to cryptographic behavior, key handling, protocol parsing, or security claims require focused tests and explicit project-owner review before integration. Do not load, request, or commit real private keys or wallet secrets.

## Ownership, Decisions, and Handoffs

Before work, every agent must:

1. Read this file, `docs/coordination/PROJECT_STATUS.md`, `docs/coordination/CURRENT_TASKS.md`, and `docs/coordination/AGENT_HANDOFF.md`.
2. Inspect `git status`, the current branch, and relevant branches/PRs; preserve all existing uncommitted changes.
3. Register or claim a task in `CURRENT_TASKS.md` with one implementation owner, scope, files, dependencies, and status before editing. If ownership or overlapping work is unclear, stop and ask the project owner.
4. Work only within the assigned scope. A separate agent may review independently but must not concurrently implement the same change.

Use a dedicated branch and preferably a separate Git worktree for independent tasks. A worktree has its own files and worktree-local state; edits are not automatically visible in another worktree. Documentation and code must be committed and integrated through the normal reviewed Git process before another workspace can rely on them. Coordinate shared-file edits explicitly.

The standard workflow is: owner assigns and registers the task; implementation owner inspects code and dependencies; owner implements the scoped change and validates it; owner updates the handoff and relevant task/change records; another agent independently reviews when appropriate; the project owner approves significant technical decisions; integration occurs through a reviewed PR. A second agent's review is not implementation ownership.

Record architectural proposals as proposed until approved. `DECISIONS.md` must identify approval status; agents must not silently change architectural decisions. The project owner retains final authority over architecture, dependencies, security decisions, task priority, and merges.

## Git Safety

- Never discard or overwrite another agent's or the user's uncommitted work.
- Never reset, rebase, or rewrite shared history without explicit authorization; never force-push.
- Never merge a PR without project-owner approval; never amend another agent's commits.
- Do not push changes unless explicitly authorized.
- Preserve experimental branches, research artifacts, vectors, and negative results.
- Do not silently modify scope, architecture, dependency policy, or security posture.
- Inspect status before and after work. Keep changes scoped to the assigned task and report every affected file.

## Coordination Records

Maintain `docs/coordination/CURRENT_TASKS.md` as the task ownership/status register, `AGENT_HANDOFF.md` as the latest agent handoff, `CHANGE_LOG.md` for significant cross-agent or architectural integration events (not ordinary Git history), and `DECISIONS.md` for proposals and approved decisions. Keep `PROJECT_STATUS.md`, `ARCHITECTURE.md`, `DEVELOPMENT_RULES.md`, `SECURITY_MODEL.md`, and `RESEARCH_REGISTER.md` evidence-based. Update records only for verified changes; do not fabricate owners, approval, test results, or progress.
