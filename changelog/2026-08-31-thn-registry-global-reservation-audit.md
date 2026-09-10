# 2026-08-31 THN registry global reservation and audit

## Implementation

- Added the TEST-only global reservation for the exact The Hair Narrative Journal hub.
- Made initial reservation, exact replay confirmation, registry updates, and append-only audit events conditional DynamoDB transactions.
- Kept the reservation after deactivation and rejected cross-domain, profile, tenant, stale-revision, stale-epoch, and conflicting-owner mutations.
- Added a closed audit record and sanitized provider failure handling.
- Restricted mutation IAM to the exact TEST operator role, approved table keys, transaction context, and no failure-value disclosure.
- Kept the private mutation Lambda disconnected from public API routes and the shared v1 handler.

## Verification

- Targeted TASK-012 matrix: 69 tests passed.
- Full bundled Python suite: 176 tests passed.
- `sam validate --lint`: valid template.
- Python compilation and `git diff --check`: passed.
- Independent review and Codex Security diff scan: no reportable findings.
- `pip-audit` and `actionlint` were unavailable locally and were not silently skipped.

## Delivery state

The changes were validated and committed locally only. No branch push, AWS deployment, registry activation, or writer enablement was performed.
