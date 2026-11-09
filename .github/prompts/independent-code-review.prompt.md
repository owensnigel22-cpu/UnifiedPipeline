---
name: independent-code-review
description: Review a change independently for correctness, regressions, security, and missing tests.
---

Read `AGENTS.md`, `docs/coordination/PROJECT_STATUS.md`, `CURRENT_TASKS.md`, and `AGENT_HANDOFF.md`. Inspect the target diff and relevant source/tests without taking implementation ownership or editing the same files. Prioritize concrete findings by severity with file/line references; assess correctness, compatibility, security claims, research boundaries, test evidence, and resource risks. Distinguish blockers from questions and residual test gaps. Do not approve a merge; the project owner decides integration.
