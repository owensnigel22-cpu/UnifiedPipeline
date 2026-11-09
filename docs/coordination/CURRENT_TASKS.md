# Current Tasks

Snapshot entered 2026-11-08. Verify PR/task state before claiming work; this register is not a live GitHub feed. One implementation owner per task. Unassigned proposals are not authorization to implement.

| Task ID | Description | Assigned agent/owner | Status | Branch | PR | Files affected / scope | Dependencies | Review status |
|---|---|---|---|---|---|---|---|---|
| M10 | ECDH, optional Coincurve ECDSA, concurrent exact M7 verification collection, and reproducible ECC benchmarks | Codex implementation; project owner review | In progress; three local commits; validation/push pending | `docs/m10-optimization-ecdh-plan` | None yet | ECDH API, Coincurve adapters, mainnet verification collection, benchmark and coordination docs | Optional Coincurve; CI and full-suite verification | Not reviewed; not merged |
| PR-31 | Review Dependabot update `actions/upload-artifact` 4 to 7 | Dependabot (change author); project owner to review | Open; not approved | `dependabot/github_actions/actions/upload-artifact-7` | #31 | Workflow action version pin(s); verify exact diff in PR | None recorded | Owner review pending |
| PR-30 | Review Dependabot update `actions/cache` 4 to 6 | Dependabot (change author); project owner to review | Open; not approved | `dependabot/github_actions/actions/cache-6` | #30 | Workflow action version pin(s); verify exact diff in PR | None recorded | Owner review pending |
| PR-03 | Review `coincurve` requirement range update | Dependabot (change author); project owner to review | Open; not approved | `dependabot/pip/coincurve-gte-19.0.1-and-lt-22.0` | #3 | `pyproject.toml`; verify exact diff in PR | Dependency/security compatibility review | Owner review pending |
| PLAN-M4.7 | Decide/assign whether to implement the planned BIP-174 Updater | Unassigned; project-owner assignment required | Planning only; no implementation owner | Not assigned | None listed | Existing `M4_7_UPDATER_PLAN.md`; proposed implementation scope is described there | Existing PSBT v0 implementation; explicit owner approval | No implementation review; plan is not authorization |
| PLAN-M5-ECDSA | Resolve decision gates and assign next ECDSA research roadmap work | Unassigned; project-owner assignment required | Proposed roadmap | Not assigned | None listed | `docs/IMPLEMENTATION_ROADMAP.md` and related research design docs | Roadmap decision gates in the source doc | No implementation review; proposal only |
| PLAN-SEC-M5 | Review/decide whether to proceed with SHA-256 preimage research plan | Unassigned; project-owner assignment required | Planning only | Not assigned | None listed | Existing `SEC_M5_SHA256_PREIMAGE_PLAN.md` | Explicit owner acknowledgment per plan | No implementation review; plan is not authorization |

## Claiming and Closing Work

Before implementation, the owner assigns one agent, confirms non-overlapping files/branches/PRs, and records scope and dependencies. Keep statuses evidence-based (for example: proposed, assigned, in progress, blocked, review, complete). Mark a task complete only after validation and handoff; do not infer approval from a green CI result. Update this register through reviewed Git changes.
