# THN production Registry reader patch for API Proxy

Date: 2026-10-01

## Incident and verified cause

The first API Proxy protected review, [run 36897395580](https://github.com/LynxPardelle/zoolanding-api-proxy/actions/runs/36897395580), passed source validation, SAM validation/build, OIDC role assumption and its identity-policy permission checks. The release stopped at the live baseline preflight before packaging or creating a change set. Its public-safe error was `production_release_failed:ClientError`.

CloudTrail shows transient `SimulatePrincipalPolicy` throttling followed by successful IAM calls, the expected missing private API stack, successful owner-stack reads and successful Cognito `DescribeUserPool` / `GetUserPoolMfaConfig`. The next call in `thn_production_prerequisites.capture` is the consistent `GetItem` for `SERVICE_BINDING#production#thn-journal-production-v2`. The live DynamoDB table resource policy has `DenyRegistryGetItemOutsideApprovedConsumers`, and its allowed-principal list omits `zoolanding-deployer-thn-auth-runtime-production-github-deploy`. A simulation using the **live resource policy** and exact binding key returns `explicitDeny`. The earlier 161/161 identity-only IAM simulation could not see that denial. No direct DynamoDB data event was available, so the CloudTrail sequence plus the exact resource-policy simulation is the bounded causal evidence; the protected review must verify the actual call after the repair.

## Options considered

1. **Source-controlled, protected CloudFormation policy patch (selected).** Add the exact API deploy role to the Registry's approved-readers exemption and its two binding-key denial statements. Create and inspect one native change set, then execute only after its digest is approved. This keeps CloudFormation and DynamoDB policy in sync.
2. Direct conditional `PutResourcePolicy`. It would be faster but would create drift from CloudFormation and bypass the reviewed release inventory. Reject.
3. Remove the Registry read from API preflight or use the human/operator inspection as a substitute. That weakens the owner-state proof and changes the trust boundary. Reject.

## Contract and scope

The patch concerns only production `zoolanding-content-hub-prod` and `ServiceBindingRegistryV2Table`. The intended role is exactly `arn:aws:iam::765932874577:role/zoolanding-deployer-thn-auth-runtime-production-github-deploy`. The policy change adds it to three existing statements:

- `DenyRegistryGetItemOutsideApprovedConsumers`: exempt the exact role from the broad read denial.
- `DenyRegistryDeploymentReadOutsideBinding`: continue to deny any key other than `SERVICE_BINDING#production#thn-journal-production-v2`.
- `DenyRegistryDeploymentReadMissingKeys`: continue to deny reads without `dynamodb:LeadingKeys`.

No other statement, principal, action, resource, condition or table property changes. The role's existing identity policy already permits `GetItem` only for the exact binding key. The complete candidate policy has been simulated with the live role: binding key `allowed`, other key `explicitDeny`, missing key `explicitDeny`. TEST policy and shared API resources stay unchanged.

## Release operation

Add a dedicated `registry-reader-patch` purpose to the Content Hub production workflow. Its candidate begins with the live Original CloudFormation template and changes only the three principal lists above. It does not rebuild or republish Lambda packages. The review checks the current protected stack, exact table identity and policy revision, verifies that the old policy matches the expected baseline, creates a change set, and accepts exactly one `Modify` of `ServiceBindingRegistryV2Table` with `Scope=[Properties]`, target `ResourcePolicy`, and `Replacement=False`. Any extra resource or parameter change aborts before execution. The reviewed digest binds source, baseline, native inventory and permission evidence. The review retains no executed resource changes.

Execution requires separate approval of the exact review run and digest. It repeats source, baseline, policy, role and inventory checks before applying. Afterwards it verifies the same 59 logical/physical resource identities, termination protection, the three exact principal additions, and the live IAM/resource-policy simulation for allowed binding and denied other/missing keys. It must also verify that activation flags, Registry row, user accounts and articles did not change. A mismatch stops the release; no automatic retry.

Before another API review, run a read-only preflight against both identity and live resource policies. Recheck the three API Environment secret names and local candidate hashes, MAIN SHA, owner stack fingerprints, Registry operator inspection, descriptor, Cognito and release bucket. The API review must then prove that its authorized deploy role can read the exact Registry row and that the row hash matches the configured prerequisite. Any new failure is diagnosed from logs and live state before another run.

## Test and promotion gates

- Unit tests reject missing, duplicate or extra principals, edits outside the three statements, other keys, missing key context, policy drift, extra change-set entries and replacement.
- Offline candidate comparison must show exactly the three additions, preserving all other template nodes and parameters.
- Run full Hub tests, SAM validation and `actionlint` when available. Promote code `dev → test → main` with source-only guards and green CI; no automatic AWS deploy.
- Run one protected production review and inspect the native inventory before requesting an execute digest. Do not launch another API Action before that policy is applied and verified.

## Boundaries

This patch does not activate Hub routes, change `writerMode`, create the owner account, update API Proxy code or publish articles. Transient IAM throttling in the failed run recovered and was not its terminal error; treat any future unrecovered throttling as a separate failure with bounded retry, not as a reason to relax policy checks.
