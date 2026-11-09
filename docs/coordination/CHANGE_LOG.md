# Coordination Change Log

Record significant cross-agent changes, shared decisions, and integration events only. Ordinary implementation history belongs in Git and release notes.

## 2026-11-08 — Initial Shared Agent Coordination

- Added a common instruction authority and assistant-specific entry points for Copilot, Claude Code, and Codex.
- Added verified project-status, architecture, development, security, research, decision, task-ownership, and handoff records, plus reusable Copilot prompts.
- Preserved existing `.claude/config.yaml`, Claude role files, project documentation, and the pre-existing untracked planning/report documents.
- Documentation/configuration only; no application source, tests, cryptographic implementation, dependencies, branches, or PRs were changed.
- Instruction activation remains host-specific and must be verified by each agent; no runtime orchestrator was installed or enabled.
