# Contributing to repo-push

Contributions to improve the auditing rules, stack-specific templates, or CI/CD pipelines are welcomed!

## Guidelines

1. **Bug fixes & Enhancements:** Open an issue first to discuss substantial additions.
2. **Verification:** Verify the schema and configuration integrity before submitting:
   ```bash
   python -c "import json, pathlib; json.loads(pathlib.Path('schemas/repo-push.schema.json').read_text()); print('schemas valid')"
   ```
3. **Auditing Protocol:** This repository implements the dynamic Orchestrator protocol (`repo-push`). During audit runs, verification subagents generate and execute on-demand inspection scripts inside `.audit/.scratch/` rather than relying on static scripts. To perform codebase audits, invoke the multi-agent preparation workflow or execute dynamic verification scripts within `.audit/.scratch/`.
4. **Pull Requests:** Provide a clear description of changes in your pull request.
