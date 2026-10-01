---
goal: Correct verified THN production activation IAM and release blockers before PR fusion
version: 1
date_created: 2026-10-01
last_updated: 2026-10-01
owner: THN release maintainers
status: 'In Progress'
tags: [infrastructure, security, production, blog]
---

# Introduction

![Status: In Progress](https://img.shields.io/badge/status-In_Progress-yellow)

Execute the approved [production activation blockers design](../docs/superpowers/specs/2026-10-01-thn-production-activation-blockers-design.md) without a speculative GitHub Action. The current remote Content Hub PR #168 remains draft at `c2cba14cced86329ef692d041e4bbeaaa0a8fb25`; the approved design is local commit `f7300a15234be60ea03fe2f5c02b5adf8ed4b78d`. No merge or AWS execution is authorized by this plan.

Local implementation is underway in the four isolated checkouts. As of 2026-10-01, no correction from this plan has been committed, pushed, promoted, or applied to AWS. Content Hub's 591 unit tests (5 skipped) and 134 release tests passed; Infra's 475 tests (1 skipped), Auth's 446 tests, and API's 334 tests (2 skipped) passed. The touched workflows passed `actionlint`. AWS CLI read-only checks confirmed the account and region, protected TEST and production Hub stacks in `UPDATE_COMPLETE`, concrete IAM decisions, and the exact names that remain available. A mocked full TEST emergency review exposed and fixed a bytes encoding error before any Action; live read-only replay then exposed an order-dependent raw hash of the TEST Registry policy, also fixed before any Action. IAM/S3 checks confirmed the guarded upload and role-policy permissions. A mocked API create-stack review traversed the exact nine-resource native inventory and retained record without AWS. The generated API production candidate passed the workflow's pinned `cfn-lint==1.56.0` and native translation; its direct three-file artifact builder passed. The complete SAM build on Windows is still limited by the missing `make` executable. A prior TEST workflow built the same Makefile on Linux, while the new production candidate still requires its protected Linux build before AWS credentials. These local checks do not substitute for a reviewed CloudFormation inventory.

The three local permission-plan drafts now cover Registry, writer IAM and emergency IAM. AWS IAM and CloudFormation read-only replay allowed all 79 Registry and 70 pairs for each IAM plan; `identity_and_permissions` accepted the plan shapes with STS identity simulated. Their source SHA is the approved local design commit `f7300a1`, so they must be regenerated and reviewed at the final MAIN SHA before any GitHub secret update or Action.

The old API activation permission plan was also stale: it named the SAM-generated role and requested ten unsupported Logs actions. A separate ignored draft now names the external role, fixed Lambda and log group. Read-only `SimulateCustomPolicy` against the proposed Infra policies allowed all 136 action/resource pairs across 17 requests, using the production driver's lower-case action normalization. The nine-resource local SAM translation and live CloudFormation provider schemas require 42 native actions, all covered by that draft. The actual API `identity_and_permissions` method then passed a read-only replay of all 17 requests and eight provider schemas, with only STS identity and IAM decisions substituted from the proposed policies. This is a proposed-policy proof, not a live effective-principal proof. Regenerate the API plan at its final MAIN SHA, apply the Infra identity patch first, then use `SimulatePrincipalPolicy` on the deployed roles before any API review Action.

Current AWS CLI verification: the exact identities stack is `ZoolandingProduction-Zoolandingpage-production-ThnDeploymentIdentities` (`UPDATE_COMPLETE`, deletion protection disabled), the Hub stack is `zoolanding-content-hub-prod` (`UPDATE_COMPLETE`, deletion protection enabled), and `zlp-thn-auth-runtime-prod-role` is absent. A Hub Registry preflight launched **before** the identity patch returns IAM `NoSuchEntity` while simulating that absent runtime role, before it can create a change set. The source design already orders Infra first; check the role's live trust and policy after Infra executes before dispatching Hub Registry. The Origin Authorizer still has a closed all-zero digest, and Cognito `journal-owner` has zero users; neither is solved by source promotions.

TEST emergency review had one additional live-only blocker: DynamoDB returned equivalent Registry policies with two different `Principal.AWS` list orders under the same revision. The old raw fingerprint intermittently rejected one order. The guard now normalizes the complete 26-statement policy before hashing; the live normalized hash matches the deployed TEST template after resolving its intrinsics. Six independent reads and a real read-only `review` path up to a local barrier before `s3:PutObject` passed. A unit test rejects a changed principal. This check remains separate from a real change-set review and execution.

The production Registry shows the same returned-order behavior. The retained import reader previously pinned a raw policy hash between review and execute and could fail with no policy change. It now pins the normalized 26-statement policy; its regression test proves stable order and rejection of a changed principal. The direct human `DescribeTable` replay is blocked by the Registry resource policy, which is expected. If the retained import operation is needed again, its protected deployment role must verify that full live path using a fresh source-bound review.

Repository paths below are relative to these four checkout roots in `C:/Users/hmcov/OneDrive/Documentos/ChatGPT/the hair narrative/`: `zoolandingpage-aws-infra-thn-guard-integration/` (Infra), `zoolanding-api-proxy-thn-guard-integration/` (API), `zoolanding-content-hub-thn-guard-integration/` (Hub), and `zoolanding-auth-admin-thn-guard-integration/` (Auth). Before editing, fetch or inspect each remote branch, retain local uncommitted work, and compare the exact target branch SHA. Do not force push.

## 1. Requirements & Constraints

- **REQ-001**: Correct the API deployment, Auth deployment and API runtime Registry read decisions on only `SERVICE_BINDING#production#thn-journal-production-v2`.
- **REQ-002**: Give the dedicated API Lambda the exact function name `zlp-thn-auth-runtime-production` and external role `zlp-thn-auth-runtime-prod-role`, after rechecking both names are unused.
- **REQ-003**: Replace all impossible API IAM/Lambda/Logs physical-name patterns in the deployed identities source, its proof catalog and the Hub writer fence.
- **REQ-004**: Restore the emergency-withdraw handler's initial exact Registry read in TEST and production without invoking a withdrawal.
- **REQ-005**: Repair the Hub writer fence's Auth main function ARN and document the separate owner, Cognito and origin-proof prerequisites.
- **SEC-001**: Simulate complete identity plus DynamoDB resource policies for exact, other and absent `dynamodb:LeadingKeys`; new exact-key grants include `Null: {"dynamodb:LeadingKeys": "false"}`.
- **SEC-002**: No wildcard principal exception, TEST principal grant in production, unrelated stack modification, replacement, article publication or client-account substitution.
- **CON-001**: Keep protected releases separate: source promotion, review inventory, explicit digest approval, execution, postcheck. Approval for this design does not authorize push, merge, secret change or AWS mutation.
- **CON-002**: Retain the existing production source route order `dev → test → main` and exact SHA/tree selectors. Confirm automatic AWS jobs are omitted on source-only pushes.
- **CON-003**: Keep raw origin proof, credentials, customer data and environment secret values out of code, logs, plans and reports.
- **GUD-001**: Before any Action, compare live account/region, stack status and protection, Original/Processed templates, parameters, resources, policy revisions, function/role names, package hashes, owner fingerprints, S3 objects and effective IAM decisions with AWS CLI.

## 2. Implementation Steps

### Implementation Phase 1

- GOAL-001: Freeze source and reproduce all known failure decisions offline and with read-only AWS.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Record exact local/remote `dev`, `test`, `main` and PR #168 SHA for Hub, API, Infra and Auth; inspect all modified/untracked files before choosing branches. | | |
| TASK-002 | Re-run the existing Hub Registry full-policy simulation, API concrete-name IAM simulation, Hub writer-dependency simulation and TEST/production emergency `GetItem` simulation. Save only decisions, policy revisions and hashes in ignored `.superpowers/`. | | |
| TASK-003 | Query AWS for collisions on `zlp-thn-auth-runtime-prod-role`, `zlp-thn-auth-runtime-production`, its log group and the dedicated API stack. Stop if any exists unexpectedly. | | |

### Implementation Phase 2

- GOAL-002: Implement source-only Infra identity and frontdoor preflight repairs. Depends on GOAL-001.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-004 | Update Auth `tools/build_thn_deployment_identities.py` and its API SAM input to generate the exact API function/role/log names and proof rows. Update Infra `tools/production/thn-deployment-identities.json` with only the generated API-group deltas and the exact Lambda-trusting runtime role, including exact-key/non-null Registry `GetItem` and exact log writes. Preserve all existing non-API entries byte-for-byte after canonical JSON comparison; do not copy Auth's whole generated manifest over Infra's current manifest. | | |
| TASK-005 | In Infra `tools/thn-production-identities.js`, `tools/thn-production-retained-review.js` and `.github/workflows/thn-production-identities.yml`, add `api-runtime-role-patch`. Candidate changes only one role Add and named API caller/execution IAM policy Modify resources; reject replacement, other changes, altered owner-pool parameter or changed termination-protection baseline. Review/execute bind exact digest and repeat pre/post IAM proof. | | |
| TASK-006 | In Infra `tools/thn-production-frontend-release.js`, reject the 64-zero Auth origin digest at the earliest private-frontdoor baseline check; retain the later SHA-256 equality check against the 43-character secret. Add an offline test using a zero digest and assert no publishing or change-set call occurs. | | |
| TASK-007 | Extend Infra `test/thn-production-identities.test.js`, `test/thn-production-retained-review.test.js` and `test/thn-production-frontend-release.test.js`; extend Auth `tests/test_thn_deployment_identities.py`. Prove exact inventories, wrong principal/key, absent key/context, short ARNs, zero digest, changed baseline and replay/digest rejection. Compare the generated API slice to Infra's API slice; assert all non-API resources and proof rows are unchanged, including the five Infra-only resources and the three Auth/two Hub native-policy revisions. Run `node --test`, `npm test` where defined and `actionlint` locally. | | |

### Implementation Phase 3

- GOAL-003: Implement the dedicated API projection and native guard for the external role. Depends on GOAL-001; integrate with GOAL-002 before deployment.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-008 | In API `tools/prepare_thn_production_template.py`, set `ThnAuthRuntimeV2Function.Properties.FunctionName` to `zlp-thn-auth-runtime-production`, set `Role` to the exact external role ARN, remove the now-ignored function `Policies`, retain `AutoPublishAlias=production`, and keep the shared API stack unchanged. | | |
| TASK-009 | In API `tools/thn_production_release.py` and `tools/run_thn_production_release.py`, change dedicated native inventory, preflight and postcheck to expect no SAM-generated `ThnAuthRuntimeV2FunctionRole` resource; verify the exact external role ARN, function name, alias, log group and package hash. Reject any additional or replacement resource. | | |
| TASK-010 | Extend API `tests/test_thn_production_template.py`, `tests/test_thn_production_release.py` and `tests/test_thn_production_native_permissions.py`. Translate the production SAM candidate offline, assert the generated role is absent and all native resources are expected, then run the full unittest suite, `sam validate --lint`, `sam build --no-cached` and `actionlint` if available. | | |

### Implementation Phase 4

- GOAL-004: Implement Hub Registry, writer and emergency corrections with separate release scopes. Depends on GOAL-001 and the exact identities from GOAL-002.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-011 | Revise Hub `tools/thn_production_release.py` and matching tests so `registry-reader-patch` starts from the live Original template; add Auth and API deploy roles to exactly three read-deny principal lists; add the new production runtime role only to the broad reader exception; remove the stale TEST runtime exception. Require a single nonreplacing `ServiceBindingRegistryV2Table.ResourcePolicy` Modify. | | |
| TASK-012 | In Hub `tools/prepare_thn_production_template.py`, replace the invalid Auth main function ARN and impossible API function pattern in `ReadExactProductionWriterServices` with exact physical function and alias ARNs; preserve Origin Authorizer, Hub Authoring and Image Upload entries. Add a bounded IAM-only production release scope and tests for only the mutation-role policy Modify. | | |
| TASK-013 | In Hub `template.yaml` and the production projection, add exact Registry `GetItem` with non-null `dynamodb:LeadingKeys` to the existing emergency-withdraw role for each environment. Add TEST and production IAM-only review guards in the corresponding release scripts/workflows if the current guards cannot express the one-role-policy inventory. Do not modify handler code or invoke withdrawal. | | |
| TASK-014 | Extend Hub `tests/test_thn_production_registry_reader_patch.py`, `tests/test_production_owner_writer_fence.py`, `tests/test_content_hub_v2_emergency_withdraw.py`, `tests_release/test_thn_test_release.py` and `tests/test_thn_production_release.py`. Exercise all five writer dependencies, Auth/API/Hub/Image/TEST reader decisions and exact/other/missing keys in both environments. Confirm the emergency handler reaches its first read through a non-mutating test. Run Hub full unittest suite, `pip-audit`, `sam validate` and `actionlint` locally. | | |

### Implementation Phase 5

- GOAL-005: Verify cross-repository source and AWS preflight before any push or Action. Depends on GOAL-002, GOAL-003 and GOAL-004.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-015 | Compare proposed role/function names and each required CloudFormation handler action against live IAM using concrete resource ARNs and required context keys; require `allowed` with no missing context for intended requests and deny for wrong/missing binding keys. Do not count wildcard pseudo-ARN simulations. | | |
| TASK-016 | Re-run local test suites, static workflow lint, SAM translation, dependency audits and all change-set inventory guards against captured live Original/Processed templates and parameters. Save hashes and redacted results; fix every failing local check before the first push. | | |
| TASK-017 | Prepare per-repo exact file/diff summaries and PR bodies. Obtain the required repository-specific approval before commit/push or merge. After approved source promotions, verify selectors and CI, recalculate permission plans and owner fingerprints at the final MAIN SHAs. | | |

### Implementation Phase 6

- GOAL-006: Release and accept the complete production flow only after separate operation approvals. Depends on GOAL-005 and client-owner participation.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-018 | Review/execute Infra `api-runtime-role-patch`, then Hub `registry-reader-patch`, each only after showing its exact native inventory and digest and obtaining separate execution approval. Verify live role trust/policies, Registry revision and service-role `GetItem`. | | |
| TASK-019 | After TASK-018, review/execute Hub writer IAM and TEST/production emergency IAM patches with separate inventories and digest approvals. Verify concrete decisions and non-mutating handler read. | | |
| TASK-020 | After TASK-019, configure the approved nonzero Auth origin digest through a protected Auth state review and verify the matching origin proof exists in an authorized secret source; require Infra private-frontdoor preflight to reject a closed digest before dispatch. Execute each reviewed change only after separate approval. | | |
| TASK-021 | After TASK-020, refresh API owner fingerprints and its source-SHA-bound secrets after Hub updates. Review API dedicated stack; execute only its approved digest. Verify exact function/role/alias, runtime `GET/POST` contract and logs. Stop on any unexpected change. | | |
| TASK-022 | After TASK-021, review/execute Infra private-frontdoor with the matching origin proof and exact production origins. Verify CloudFront, DNS, certificate and Auth header digest before inviting browser enrollment. | | |
| TASK-023 | After TASK-022, review/execute Auth owner-operator state only with the exact approved human principal, then complete client-owner/MFA enrollment with the owner. Verify exactly one enabled owner and matching state. Review the Hub owner-pool parameter transition from `BLOCKED` with its IAM/Lambda inventory, then simulate all four Cognito calls. | | |
| TASK-024 | After TASK-023, refresh Auth/Hub/Image prerequisite secrets from live owner state and final MAIN SHAs. Review and execute each service activation separately; verify admin login, blog read/write and image behavior with the client owner without publishing an article. | | |

## 3. Alternatives

- **ALT-001**: API-owned explicit role inside the API stack reduces one identities release but prevents staged proof that the runtime reader principal exists before the Registry policy review.
- **ALT-002**: Wider wildcard IAM/Registry exceptions risk granting another environment's role; reject.
- **ALT-003**: Direct DynamoDB `PutResourcePolicy` creates CloudFormation drift and bypasses the reviewed inventory; reject.

## 4. Dependencies

- **DEP-001**: Approved design commit `f7300a15234be60ea03fe2f5c02b5adf8ed4b78d`; user approved this exact version. Check that it remains the source contract before implementation.
- **DEP-002**: AWS account 765932874577, region us-east-1, valid read-only CLI session, source repository access and installed local toolchains.
- **DEP-003**: Production client owner participation and software-token MFA before owner enrollment or writer activation.
- **DEP-004**: Explicit approvals required by repository `AGENTS.md`, protected workflows and reviewed change-set digests for push, merge, secret updates and AWS execution.

## 5. Files

- **FILE-001**: Infra `tools/production/thn-deployment-identities.json`, `tools/thn-production-identities.js`, `tools/thn-production-retained-review.js`, `.github/workflows/thn-production-identities.yml`, `tools/thn-production-frontend-release.js`, `test/thn-production-identities.test.js`, `test/thn-production-retained-review.test.js`, `test/thn-production-frontend-release.test.js`.
- **FILE-002**: API `tools/prepare_thn_production_template.py`, `tools/thn_production_release.py`, `tools/run_thn_production_release.py`, `tests/test_thn_production_template.py`, `tests/test_thn_production_release.py`, `tests/test_thn_production_native_permissions.py`.
- **FILE-003**: Hub `tools/thn_production_release.py`, `tools/run_thn_production_release.py`, `tools/run_thn_production_import.py`, `tools/thn_test_emergency_iam.py`, `tools/prepare_thn_production_template.py`, `template.yaml`, `.github/workflows/deploy-thn-production.yml`, `.github/workflows/thn-test-emergency-iam.yml`, and the related Registry/IAM/emergency/import tests.
- **FILE-004**: Auth `tools/build_thn_deployment_identities.py`, `tools/production/thn-deployment-identities.json` and `tests/test_thn_deployment_identities.py` provide the baseline identity manifest and compiler. Infra's manifest has five later resources (`ConfigAuthoringRequiredReadPolicy`, `ConfigRuntimeCfnPackageReadPolicy`, `ConfigRuntimeDeployRequiredReadPolicy`, `HubImportPreflightReadPolicy`, `ThnProductionSamTransformPolicy`) and revised `AuthCfnNativePolicy1`/`2`/`3` and `HubCfnNativePolicy2`/`3` versus fresh compiler output; preserve these as an explicit overlay rather than overwriting them with Auth's output. Later owner-operator and digest releases use existing guarded Auth source and require separately reviewed parameter sets.

## 6. Testing

- **TEST-001**: Full Registry policy simulation for Auth/API deploy, production runtime, Hub/Image deploy and stale TEST runtime with exact, other and missing keys.
- **TEST-002**: Concrete IAM action/resource simulation for API caller/CloudFormation and all writer-fence dependencies; no missing context or wildcard pseudo-ARN counted as success.
- **TEST-003**: SAM translation confirms explicit API function and external role, no generated role and exact retained log group; native guards reject extras and replacement.
- **TEST-004**: Emergency handler first-read test in TEST and production is non-mutating and succeeds with exact-key IAM; other/missing-key simulations deny.
- **TEST-005**: Frontdoor baseline rejects zero digest before S3 publishing or change-set creation; origin proof and Auth digest match without logging secret bytes.
- **TEST-006**: CI, approved native inventories, post-execution identities, owner state and user-facing QA pass for the full production route. A green PR check alone is insufficient.

## 7. Risks & Assumptions

- **RISK-001**: CloudFormation may report conditional dependent changes. Execute only inventories explicitly allowlisted and reviewed; stop if any replacement or unrelated resource appears.
- **RISK-002**: A role, function, log group or stack could be created by another actor after the collision check. Recheck immediately before review and execution.
- **RISK-003**: GitHub Environment/repository metadata shows no Infra production origin secret; organization-secret visibility is unavailable. Prove secret resolution through authorized metadata or a protected preflight, not an assumption.
- **RISK-004**: Historical change sets are gone for some failures. Treat their sanitized logs as bounded evidence and do not claim an unobservable root cause.
- **RISK-005**: Auth's generated identity manifest already differs from Infra's deployed-source manifest. Wholesale regeneration would remove five later resources and roll back three Auth and two Hub policies. Compare the API slice and the explicit overlay separately before any commit.
- **ASSUMPTION-001**: The client owner will be available for enrollment and MFA after the infrastructure is ready. Until then, owner and writer activation cannot be accepted.

## 8. Related Specifications / Further Reading

- [Approved production activation design](../docs/superpowers/specs/2026-10-01-thn-production-activation-blockers-design.md)
- [Original narrow Registry reader design](../docs/superpowers/specs/2026-10-01-thn-production-api-registry-reader-patch-design.md)
- Local ignored evidence: `.superpowers/registry-reader-premerge-review-20261001.md`
- AWS CloudFormation IAM Role name limit: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-role.html
- AWS SAM Function `Role` and `Policies` behavior: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html
