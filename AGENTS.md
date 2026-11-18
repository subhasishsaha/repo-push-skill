# Agent Instructions: Orchestrator-Driven Codebase Preparation Protocol

This repository implements the **`repo-publish-prep`** protocol — an orchestrator-driven multi-agent verification system for preparing, auditing, sanitizing, and packaging codebases for GitHub, GitLab, Bitbucket, and remote Git hosting.

## The Orchestrator Protocol & Behavioral Isolation

The primary agent must act as the **Orchestrator**, coordinating specialized subagents (`explorer`, `documenter`, `auditor`, `remediator`) rather than performing audits directly.

### Behavioral Isolation Contracts (`.audit/.agents/`)
To prevent subagents from overstepping their scope (e.g. `remediator` editing `auditor`'s report), the Orchestrator injects behavioral contracts from `.audit/.agents/`:
- **`explorer.md`**: Permitted writes: `.audit/reports/explorer_report.md` & `.audit/.scratch/`. Forbidden: `README.md`, application code.
- **`documenter.md`**: Permitted writes: `README.md`. Forbidden: `.audit/reports/`, application code.
- **`auditor.md`**: Permitted writes: `.audit/.scratch/` & `.audit/reports/auditor_report.md`. Forbidden: ANY application code or `README.md`.
- **`remediator.md`**: Permitted writes: Application code & configs. **CRITICAL RESTRICTION: MUST NEVER TOUCH `.audit/reports/` (INCLUDING `auditor_report.md` AND `final_report.md`)!** All audit reports are strictly owned by the auditor and the Orchestrator.

Subagents dynamically create their own targeted audit and discovery scripts in `.audit/.scratch/` for each run.

### Phase 1: README Verification Gate
1. **If README.md exists:**
   - Read `README.md` and verify with the user if it matches intended application behavior.
   - If drifted, **stop execution immediately** and ask for clarification.
   - If verified, proceed to Phase 2.
2. **If README.md is missing:**
   - Orchestrator spawns `explorer` (Codebase Archeologist) to inspect code and draft findings in `.audit/reports/explorer_report.md` (`explorer` never writes the README).
   - Orchestrator spawns `documenter` (Verifier) to independently check Explorer's report against the code.
   - If verification fails, `explorer` discards and re-runs.
   - Once verified, `documenter` drafts `README.md` and submits it to user for confirmation.

### Phase 2: Implementation Integrity Loop (Auditor ⇄ Remediator)
1. **Launch `auditor` (Adversarial Auditor):**
   - Pure audit role (no code edits).
   - Writes on-demand audit scripts in `.audit/.scratch/` to check:
     - Eagerness bias & stubs
     - Undeclared packages / import errors
     - Hardcoded developer paths (`C:\Users\...`, `/home/...`) & IPs
     - Document-to-code drift
     - Secret leaks
   - Writes report to `.audit/reports/auditor_report.md`.
2. **Launch `remediator` (Remediation Engineer):**
   - Implements full, production-grade fixes as specified in `auditor_report.md`.
   - Leaves `.audit/reports/` completely untouched.
   - Returns control to `auditor`.
3. **Re-verification Loop:**
   - `auditor` re-runs its audit in `.audit/.scratch/`. When all checks pass, Phase 2 is complete.

### Phase 3: Final Certification
1. Write the final certification report to `.audit/reports/final_report.md`.
2. Present the executive summary to the user and stage clean Git commits.


---

# Universal Memory Hook Protocol (.memory/)

This repository is integrated with the **Cross-Provider Memory Hook**.
All agent activities (user requests, tool calls, tool responses, model outputs) are deterministically recorded in `.memory/short.log`, maintaining a rolling context window of **100,000 tokens** (100k tokens).

## Core Directives for All Agents:

1. **Context Restoration at Session Start**:
   - At the beginning of every session or task, read `.memory/long.log` first.
   - If needed, read the tail of `.memory/short.log` (last 20-30 lines) to catch up on the most recent actions taken by any previous agent (Claude, Antigravity, Codex, Cursor).
   - Never ask the user to re-explain what the project is about or what has already been built.

2. **Long-Term Memory Compaction**:
   - Whenever you receive a `[MEMORY HOOK UPDATE NOTICE]` indicating ~10,000 tokens have accumulated, review the uncompacted tail of `.memory/short.log` alongside the existing `.memory/long.log`.
   - Use your model tools (`edit_file` or `write_file`) to update `.memory/long.log`:
     - Update the header metadata: `Last Updated`, `Provider`, and `Synced Through Event: #<seq>`.
     - Update **Completed Work & Milestones** with newly finished items.
     - Update **Current State & Active Focus** with what you are working on right now.
     - Update **Next Immediate Steps** with pending tasks.
     - Preserve and append any newly established **Architecture & Core Decisions**.
     - Keep content concise, high-density, and structured.

3. **Security & Immutability Directives**:
   - The runner at `.memory/bin/memory_hook_runner.pyc` is locally compiled bytecode locked with OS read-only permissions.
   - Under NO circumstances should any agent attempt to edit, rewrite, replace, or delete files inside `.memory/bin/` or `.memory/state.json`.
   - All memory updates must strictly be applied to `.memory/long.log`.
