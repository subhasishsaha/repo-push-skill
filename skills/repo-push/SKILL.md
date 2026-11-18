---
name: repo-push
description: Orchestrator protocol for multi-agent adversarial codebase preparation and push. The coordinator spawns and manages subagents (Explorer, Documenter, Auditor, Remediator). Subagents write their own dynamic audit scripts in '.audit/.scratch/' and strictly adhere to behavioral isolation contracts stored in '.audit/.agents/'.
license: Apache-2.0
metadata:
  version: v4
  architecture: orchestrator-subagent-behavioral-isolation
  compatibility: universal-agent-agnostic
---

# Repository Push & Hosting Preparation (`repo-push`)

An orchestrator-driven multi-agent verification protocol that guarantees **truth in code and documentation** before publishing or pushing to GitHub, GitLab, Bitbucket, or remote Git hosting.

The primary coordinator acts as the **Orchestrator**. It does not perform audits directly; it defines, spawns, and coordinates specialized **subagents** (`explorer`, `documenter`, `auditor`, `remediator`).

---

## 🛡️ In-Memory Behavioral Isolation Contracts

To prevent subagents from overstepping their scope—such as **`remediator` editing `auditor`'s report** instead of fixing the application code—the Orchestrator injects strict behavioral isolation contracts directly **in-memory** into each subagent's system prompt.

> **Zero Disk Clutter Guarantee:** No `.audit/.agents/` folder or contract files are written to disk in target repositories. The Orchestrator injects the contracts directly when calling `define_subagent` and `invoke_subagent`.

---

## 🏗️ Orchestration Flowchart

```mermaid
flowchart TD
    Start["🚀 Orchestrator Starts"] --> CheckReadme{"Does README.md exist?"}
    
    %% Phase 1
    CheckReadme -->|Yes| VerifyWithUser["Prompt User: Does README match intended application behavior?"]
    VerifyWithUser -->|User: Drifted / Wrong| HaltUser["🛑 Halt Execution Immediately & Ask User for Clarification"]
    VerifyWithUser -->|User: Verified OK| Phase2["Proceed to Phase 2"]
    
    CheckReadme -->|No| LaunchExp["Orchestrator injects Explorer Contract in-memory\nSpawns Explorer"]
    LaunchExp --> ExpWork["Explorer inspects code, creates scratch scripts in .audit/.scratch/\nWrites .audit/reports/explorer_report.md\n(STRICT: Never writes README.md)"]
    ExpWork --> LaunchDoc["Orchestrator injects Documenter Contract in-memory\nSpawns Documenter"]
    LaunchDoc --> DocVerify{"Documenter verifies code on disk.\nDoes Explorer report match truth?"}
    DocVerify -->|Fails / Discrepancy| ExpRetry["Reject report with diff.\nExplorer discards & re-runs"]
    ExpRetry --> ExpWork
    DocVerify -->|Passes| DocDraft["Documenter writes README.md"]
    DocDraft --> VerifyNewReadme["Prompt User: Verify newly generated README.md"]
    VerifyNewReadme --> Phase2

    %% Phase 2
    Phase2 --> LaunchAud["Orchestrator injects Auditor Contract in-memory\nSpawns Auditor"]
    LaunchAud --> AudWork["Auditor creates on-demand audit scripts in .audit/.scratch/:\n- AST stubs & eagerness bias\n- Import errors & undeclared packages\n- Hardcoded developer paths & IPs\n- Markdown link & doc drift\nWrites findings to .audit/reports/auditor_report.md\n(STRICT: Makes NO application code edits)"]
    AudWork --> CheckIssues{"Are there blockers / issues?"}
    CheckIssues -->|No Issues| Phase3["Proceed to Phase 3"]
    CheckIssues -->|Issues Found| LaunchRem["Orchestrator injects Remediator Contract in-memory\nSpawns Remediator"]
    LaunchRem --> RemWork["Remediator implements full, un-stubbed fixes in code\n(STRICT: NEVER touches .audit/reports/)"]
    RemWork --> AudRecheck["Orchestrator returns control to Auditor\nRe-runs dynamic audit in .audit/.scratch/"]
    AudRecheck --> CheckIssues

    %% Phase 3
    Phase3 --> FinalReport["Orchestrator generates Final Certification at:\n.audit/reports/final_report.md"]
    FinalReport --> PresentUser["Present Certification & Executive Summary to User"]
```

---

## 🛠️ Dynamic Scripting Workspace: `.audit/.scratch/`

Instead of brittle static scripts, subagents write purpose-built scripts directly in `.audit/.scratch/`:
- **`explorer`** writes dynamic AST inspection or entrypoint discovery scripts in `.audit/.scratch/` to explore unknown repos.
- **`auditor`** writes specialized Python, Node, or Shell scripts in `.audit/.scratch/` to test:
  1. Stubs, empty functions (`pass`, `...`), and `raise NotImplementedError`.
  2. Imports vs manifests (`package.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `go.mod`).
  3. Absolute paths (`C:\Users\...`, `/home/...`) and internal private IPs.
  4. Broken relative Markdown links and documented entrypoints.
- `.audit/` (including `.audit/.scratch/`) is ignored in `.gitignore` so temporary audit scripts never dirty the repository.

---

## 🤖 The 4 In-Memory Subagent Behavioral Boundaries

The Orchestrator defines and spawns each subagent by injecting its explicit boundary contract directly into the subagent's `SystemPrompt` and task instructions (no contract files are created on disk in target repositories):

### 1. `explorer` — Codebase Archeologist
- **Role:** Explores repository structure, architecture, and capabilities; drafts objective findings.
- **Permitted Writes:** `.audit/.scratch/*`, `.audit/reports/explorer_report.md`.
- **FORBIDDEN:** Creating or editing `README.md`, editing application source code, editing `.audit/reports/final_report.md` or `.audit/reports/auditor_report.md`.

### 2. `documenter` — Independent Verifier & Technical Writer
- **Role:** Independently verifies explorer findings line-by-line against actual source code; drafts `README.md`.
- **Permitted Writes:** `README.md` at repository root.
- **FORBIDDEN:** Modifying `.audit/reports/explorer_report.md` or any file in `.audit/reports/`, editing application code, inventing ungrounded features.

### 3. `auditor` — Adversarial Codebase Auditor
- **Role:** Dynamically writes and runs AST and security audit scripts in `.audit/.scratch/`; writes findings report.
- **Permitted Writes:** `.audit/.scratch/*`, `.audit/reports/auditor_report.md`.
- **FORBIDDEN:** Modifying application source code files, editing `README.md`, editing package manifests. Sole maintainer of the audit report.

### 4. `remediator` — Remediation Engineer
- **Role:** Implements full, un-stubbed production code and config fixes to resolve findings in `auditor_report.md`.
- **Permitted Writes:** Application source code files, package manifests (`package.json`, `requirements.txt`), repository hygiene files (`.gitignore`, `.editorconfig`, `.env.example`, `CONTRIBUTING.md`, `SECURITY.md`).
- **CRITICAL RESTRICTION:** **MUST NEVER TOUCH, EDIT, OR MODIFY `.audit/reports/` (INCLUDING `auditor_report.md` AND `final_report.md`)!**
  - All audit reports belong exclusively to the auditor and Orchestrator.
  - The `remediator` must NEVER edit the report to check off boxes or delete findings.
  - The `remediator` fixes the issues in actual source code. The `auditor` independently re-audits the code and updates the report itself.
  - Zero stubs: No `pass`, no ellipsis, no placeholder comments, no mock bypasses.

---

## 🔄 Orchestrator Execution Protocol

### Step 0: Pre-Flight Setup
Ensure `.audit/reports/` exists. No contract files need to be written to disk in target repositories; all behavioral contracts are injected directly in-memory by the Orchestrator.

### Phase 1: README Verification Gate
1. Check if `README.md` exists.
2. If `README.md` exists:
   - Ask the user: *"Does this README accurately represent what the application is intended to do, or has it drifted?"*
   - If user signals drift: **Halt execution immediately.** Ask for clarification before proceeding.
   - If user confirms: Proceed to Phase 2.
3. If `README.md` is missing:
   - Orchestrator injects the in-memory Explorer contract and spawns `explorer`. The `explorer` writes `.audit/reports/explorer_report.md`.
   - Orchestrator injects the in-memory Documenter contract and spawns `documenter`. The `documenter` verifies. If failed, loops back to `explorer` (Max 3 iterations). Once passed, `documenter` drafts `README.md`.
   - Present newly drafted `README.md` to user for explicit confirmation.

### Phase 2: Implementation Integrity Loop
1. Orchestrator ensures directory `.audit/.scratch/` exists.
2. Orchestrator injects the in-memory Auditor contract and invokes `auditor`.
3. `auditor` writes its inspection scripts into `.audit/.scratch/`, runs them, and outputs `.audit/reports/auditor_report.md`.
4. Orchestrator reads `.audit/reports/auditor_report.md`.
5. If blockers or warnings exist:
   - Orchestrator injects the in-memory Remediator contract and invokes `remediator` with the action items.
   - `remediator` implements real code fixes. It strictly leaves `.audit/reports/` untouched.
   - Orchestrator hands control back to `auditor` to re-execute its scratch audit.
   - Loop repeats until 0 blockers remain (Circuit breaker: Max 3 iterations, then escalate to user).

### Phase 3: Final Certification & Ledger
1. When the `auditor` confirms 0 blockers remain, Orchestrator compiles and writes:
   ```text
   .audit/reports/final_report.md
   ```
   Adhering to [templates/audit/final_report.template.md](./templates/audit/final_report.template.md).
2. Orchestrator verifies `git status`.
3. Orchestrator presents the final certification summary to the user.
