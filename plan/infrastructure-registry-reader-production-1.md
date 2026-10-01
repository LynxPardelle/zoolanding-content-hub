---
goal: Add a protected production Registry reader patch for the API deployment role
version: 1.0
date_created: 2026-10-01
last_updated: 2026-10-01
owner: THN Content Hub
status: 'In progress'
tags: [infrastructure, production, registry, release]
---

# Introduction

![Status: In progress](https://img.shields.io/badge/status-In%20progress-yellow)

The API Proxy production review failed because the live Registry table policy explicitly denies its deployment role. This plan adds a guarded Content Hub release purpose that modifies only that policy and verifies the exact access boundary before another API Action.

## 1. Requirements & Constraints

- **REQ-001**: Add only `arn:aws:iam::765932874577:role/zoolanding-deployer-thn-auth-runtime-production-github-deploy` to the three approved Registry read conditions in production.
- **REQ-002**: Construct the candidate from the live Original CloudFormation template, preserving every other template node and parameter.
- **SEC-001**: Require one native nonreplacing `ServiceBindingRegistryV2Table` ResourcePolicy modification; reject extra inventory entries.
- **SEC-002**: Verify the exact binding is allowed and other or missing keys are explicitly denied using the complete live resource policy.
- **CON-001**: Preserve all 59 physical identities, closed routes, Registry data, and operator settings.
- **CON-002**: Review and execute are distinct protected operations bound to source SHA and approved digest.
- **GUD-001**: Complete local tests and live read-only checks before any GitHub Action.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Encode exact candidate and review guards.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Add `registry-reader-patch` to `tools/thn_production_release.py` with a candidate function that changes exactly three statement principal lists in `ServiceBindingRegistryV2Table`; reject duplicate, missing, and changed statements. | ✅ | 2026-10-01 |
| TASK-002 | Add a one-resource native inventory guard to `tools/thn_production_release.py`; require `Modify`, `Properties/ResourcePolicy`, and `Replacement=False`. | ✅ | 2026-10-01 |
| TASK-003 | Extend `tools/run_thn_production_release.py` to select the live-template candidate, preserve all parameters, fingerprint the live policy revision, and repeat the same guards before execution. | ✅ | 2026-10-01 |

### Implementation Phase 2

- GOAL-002: Integrate the guarded purpose into the workflow and prove local behavior.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-004 | Add the purpose to `.github/workflows/deploy-thn-production.yml` and skip SAM build/package while retaining validation, source check, identity, preflight, review artifact, and execute checks. | ✅ | 2026-10-01 |
| TASK-005 | Add rejection and success tests in `tests/test_thn_production_registry_reader_patch.py`; run full Python suite, `sam validate`, `actionlint`, and `pip-audit -r requirements.txt` when available. | ✅ | 2026-10-01 |
| TASK-006 | Compare the local candidate against live AWS templates, policy revision, exact role, protected stack and identity inventory; simulate exact, other, and missing keys with the complete policy. | ✅ | 2026-10-01 |

### Implementation Phase 3

- GOAL-003: Promote source and apply only an approved native inventory.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-007 | After local checks and required approvals, integrate through `dev`, `test`, `main` with source-only promotion and green mandatory CI. | | |
| TASK-008 | Run one protected production review, inspect the inventory and digest, and obtain separate execution approval. | | |
| TASK-009 | Execute only the approved digest, verify the unchanged 59 resource identities and policy outcomes, then retry one API Proxy protected review only after its preflight passes. | | |

## 3. Alternatives

- **ALT-001**: Direct DynamoDB `PutResourcePolicy` creates CloudFormation drift and bypasses the retained review; rejected.
- **ALT-002**: Removing the Registry read from API preflight weakens owner-state verification; rejected.

## 4. Dependencies

- **DEP-001**: Live production Content Hub stack and policy must match the captured read-only baseline.
- **DEP-002**: Production deploy and execution roles must have effective permissions for native table policy modification.

## 5. Files

- **FILE-001**: `tools/thn_production_release.py` for candidate and inventory checks.
- **FILE-002**: `tools/run_thn_production_release.py` for protected CLI lifecycle.
- **FILE-003**: `.github/workflows/deploy-thn-production.yml` for purpose selection.
- **FILE-004**: `tests/test_thn_production_release.py` and a dedicated driver test file for regression coverage.

## 6. Testing

- **TEST-001**: Reject all policy edits beyond the three exact principal additions and any duplicate principal.
- **TEST-002**: Reject extra changes, replacement, wrong target and changed parameters.
- **TEST-003**: Prove exact binding `allowed`, other key `explicitDeny`, missing key `explicitDeny` with the full candidate policy.
- **TEST-004**: Verify post-execution template, policy, 59 identities and closed activation inputs.

## 7. Risks & Assumptions

- **RISK-001**: CloudFormation may present unexpected native dependencies; the inventory guard must stop before execution.
- **RISK-002**: DynamoDB policy representation may reorder principals; compare semantic content with a narrowly defined normalizer.
- **ASSUMPTION-001**: The 59-resource stack remains `UPDATE_COMPLETE` and termination protected until review.

## 8. Related Specifications / Further Reading

- [Approved production Registry reader patch design](../docs/superpowers/specs/2026-10-01-thn-production-api-registry-reader-patch-design.md)
