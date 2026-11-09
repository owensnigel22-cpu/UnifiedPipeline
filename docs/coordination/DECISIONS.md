# Decisions and Proposals

This log records coordination and architectural decisions with explicit approval state. A proposal is not an approved decision. Significant changes require project-owner approval.

## Entry Format

- **Identifier:** stable ID
- **Date:** YYYY-MM-DD
- **Context:** problem and verified facts
- **Alternatives:** considered options
- **Decision:** selected option or proposal
- **Reasoning:** why
- **Consequences:** impact, risks, follow-up
- **Approval status:** proposed / owner-approved / rejected / superseded, with approver/evidence when known

---

## COORD-0001: Shared AI Coordination Records

- **Identifier:** COORD-0001
- **Date:** 2026-11-08
- **Context:** The project owner requested a common instruction and handoff system for Copilot, Claude Code, and Codex. Existing repository docs already define project security, research, tests, and architecture; existing `.claude/config.yaml` explicitly does not activate runtime orchestration.
- **Alternatives:** Keep assistant-specific instructions separate; add a shared authoritative `AGENTS.md` with short assistant-specific entry points; introduce an automated agent orchestrator.
- **Decision:** Establish repository documentation/configuration with `AGENTS.md` as the shared authority, concise assistant entry points, and human-maintained task/handoff/decision registers. No automated orchestration is introduced.
- **Reasoning:** One shared policy reduces contradictory instructions while keeping project knowledge in versioned repository files and respecting each host's distinct instruction-loading behavior.
- **Consequences:** Agents must read and follow the common records; changes are shared only after normal Git integration. Host configuration must still be verified independently. This decision changes no application code, dependency, cryptographic behavior, or product architecture.
- **Approval status:** Owner-directed for this documentation task. This is not approval of any product architecture, security, dependency, or research proposal.

## Future Decision Template

Copy the entry format above. Do not change the approval status to owner-approved without explicit project-owner approval and a traceable record.
