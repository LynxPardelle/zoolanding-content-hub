# THN validation-only candidate

Date: 2026-09-07 (Central Time)

- Add an isolated GitHub validation workflow triggered only by `codex/thn-task029-content-hub`.
- The job has read-only repository permissions, no cloud credentials or environment approval, and no deployment or promotion step.
- Run the owning repository's tests and build checks; retain an explicitly non-deployable candidate package and source/run/digest receipt for 30 days.
- Existing deployment triggers, activation defaults and other drafts are unchanged. The artifact is QA evidence, not a legacy recovery migration or a deployment authorization.

Validation: parsed workflow boundary checks and Actionlint. Remote test results belong to the corresponding GitHub run, not this source document.

The isolated QA workflow uses cfn-lint 1.56.0 in a separate environment to avoid
the bundled validator's obsolete SAM-generated conditional warnings. No rule
is ignored and no warning threshold is relaxed. SAM still builds the package;
the service template and runtime remain unchanged by this correction.
