# DocX Pull Request Audit Integration

This directory is the Integration Repository source set. Publish only this directory to the public Integration Repository.

It contains:

- Reusable Audit Workflow: `.github/workflows/reusable-docx-audit.yml`
- Consumer Workflow template: `consumer-repository/.github/workflows/docx-pull-request-audit.yml`
- Repository-neutral second Consumer Workflow fixture: `repository-neutral-second-consumer/.github/workflows/docx-pull-request-audit.yml`
- Reusable Audit Maintenance Workflow: `.github/workflows/reusable-docx-audit-maintenance.yml`
- Consumer Audit Maintenance template: `consumer-repository/.github/workflows/docx-pull-request-audit-maintenance.yml`
- Helper scripts: `scripts/`
- Tests: `tests/`

It must not contain DocX source code or a Prebuilt DocX Binary. The Consumer Repository owns the extension build. The Reusable Audit Workflow validates the pull request and Extension Bundle Artifact before the Binary Download Token is available to any step.
