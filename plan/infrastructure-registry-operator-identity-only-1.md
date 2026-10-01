---
goal: Correct the THN production Registry operator release after rollback
version: 1.0
date_created: 2026-10-01
last_updated: 2026-10-01
owner: THN Content Hub
status: 'Completed'
tags: [infrastructure, production, registry, iam]
---

# Introduction

![Status: Completed](https://img.shields.io/badge/status-Completed-brightgreen)

Implement the approved identity-only production operator grant locally, then verify it against the rolled-back production stack before any remote action.

## 1. Requirements & Constraints

- **REQ-001**: Keep the TEST source template's operator permission unchanged and omit `ServiceBindingRegistryOperatorInvokePermission` only from the production projection.
- **REQ-002**: Build `operator-patch` from the deployed Original template, removing exactly the dormant permission definition.
- **REQ-003**: Accept `UPDATE_ROLLBACK_COMPLETE` only when normalization of its status field gives baseline SHA-256 `06d5ee8e96c46ccd9e5a52d6305289829075eb8867d2fa95e76ca43c3472efb8`.
- **REQ-004**: Require exactly two nonreplacing native Adds: `ThnProductionRegistryHumanOperatorRole` and `ServiceBindingRegistryOperatorInvokePolicy`.
- **REQ-005**: Require 59 resources and preservation of all 57 prior physical identities after execution.
- **SEC-001**: Keep MFA trust, exact role and Lambda scope, closed routes, and unchanged Lambda resource policy.
- **CON-001**: Do not push, dispatch GitHub Actions, or change AWS during local implementation and verification.
- **CON-002**: The failed review digest is invalid and must never be reused.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Encode the approved behavior as failing tests.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Add production projection test in `tests/test_thn_production_template.py` asserting the permission is absent while `template.yaml` retains it; run that test and record expected failure. | ✅ | 2026-10-01 |
| TASK-002 | Add baseline, candidate, inventory, and completion tests in `tests/test_thn_production_postimport.py` and `tests/test_thn_production_release.py` for rollback hash and two Adds; run focused tests and record expected failures. | ✅ | 2026-10-01 |
| TASK-003 | Add IAM role trust, inline policy, and unchanged Lambda resource policy tests in `tests/test_thn_production_postimport.py`; run focused tests and record expected failures. | ✅ | 2026-10-01 |

### Implementation Phase 2

- GOAL-002: Implement the minimal production projection and release guards.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-004 | Update `tools/prepare_thn_production_template.py` to omit only `ServiceBindingRegistryOperatorInvokePermission` from the production projection; pass TASK-001 test. | ✅ | 2026-10-01 |
| TASK-005 | Update `tools/run_thn_production_release.py` to remove the dormant permission from the deployed candidate, accept only the pinned rollback baseline, validate 59 resources and exact template delta, and verify effective IAM scope after execution; pass TASK-002 and TASK-003 tests. | ✅ | 2026-10-01 |
| TASK-006 | Update `tools/thn_production_release.py` to allow exactly two operator Adds and the one approved template removal; pass inventory tests. | ✅ | 2026-10-01 |

### Implementation Phase 3

- GOAL-003: Verify all local and read-only production preflight evidence before remote release.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-007 | Run full unit tests, dependency audit, SAM validation, CloudFormation lint, and actionlint; record exact results. | ✅ | 2026-10-01 |
| TASK-008 | Compare read-only AWS stack, templates, parameters, IAM and Lambda policies with the approved baseline and simulate the reduced IAM permission plan; stop on mismatch. | ✅ | 2026-10-01 |
| TASK-009 | Record the correction and verification in `changelog/`; prepare a PR preview without pushing. | ✅ | 2026-10-01 |

## 3. Alternatives

- **ALT-001**: Add `DependsOn` to the Lambda permission. Rejected because same-account identity-based IAM invoke permission is sufficient and the permission is redundant.

## 4. Dependencies

- **DEP-001**: Approved design `docs/superpowers/specs/2026-10-01-thn-production-registry-operator-identity-only-design.md`.
- **DEP-002**: Read-only AWS CLI access to account `765932874577` in `us-east-1` for TASK-008.

## 5. Files

- **FILE-001**: `tools/prepare_thn_production_template.py` production projection.
- **FILE-002**: `tools/run_thn_production_release.py` protected review and post-execution guards.
- **FILE-003**: `tools/thn_production_release.py` native inventory guard.
- **FILE-004**: `tests/test_thn_production_template.py`, `tests/test_thn_production_postimport.py`, and `tests/test_thn_production_release.py`.
- **FILE-005**: `changelog/` correction record.

## 6. Testing

- **TEST-001**: Focused tests fail before implementation and pass after each corresponding implementation step.
- **TEST-002**: `python -m unittest discover -s tests -p "test_*.py"` passes.
- **TEST-003**: `pip-audit -r requirements.txt`, `sam validate`, CloudFormation lint, and `actionlint` pass when available.
- **TEST-004**: Read-only AWS preflight matches the pinned rolled-back baseline and reduced permission simulation.

## 7. Risks & Assumptions

- **RISK-001**: The live production stack may drift after the local comparison; a future protected review must re-check it.
- **RISK-002**: A new native change set may differ from local projection; the release guard must reject any extra action.
- **ASSUMPTION-001**: The operator role is still absent and the stack retains exactly 57 resources.

## 8. Related Specifications / Further Reading

- [Approved operator correction](../docs/superpowers/specs/2026-10-01-thn-production-registry-operator-identity-only-design.md)
- [AWS Lambda permissions](https://docs.aws.amazon.com/lambda/latest/dg/lambda-permissions.html)
