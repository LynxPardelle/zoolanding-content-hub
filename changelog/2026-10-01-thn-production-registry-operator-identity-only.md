# THN production Registry operator: identity-only correction

## Incident

The approved `operator-patch` execution `36817290193` rolled back when the new
Lambda resource-based permission rejected a role principal that CloudFormation
was still creating. The role ARN was constructed without a resource reference,
so the two resources were scheduled concurrently. Production returned to
`UPDATE_ROLLBACK_COMPLETE` with its original 57 resources.

## Local correction

- Keep the TEST template unchanged. The production projection omits only
  `ServiceBindingRegistryOperatorInvokePermission`; the same-account IAM inline
  policy grants exact invocation to the new MFA-protected human role.
- Build the one-time `operator-patch` candidate from the deployed Original
  template and remove only the dormant permission definition. The native
  inventory guard now accepts only the role and inline policy as two
  nonreplacing additions.
- Accept the rolled-back stack only when normalizing its status to
  `UPDATE_COMPLETE` gives the prior reviewed full baseline hash
  `06d5ee8e96c46ccd9e5a52d6305289829075eb8867d2fa95e76ca43c3472efb8`.
- Keep the two parameter changes and 18 preserved values, all 57 prior
  physical resource identities, closed routes and the Lambda resource policy.
  Completion requires 59 resources and verifies the new role's effective
  invoke scope with IAM simulation.

## Read-only preflight

- AWS CLI and SDK confirmed account `765932874577`, `us-east-1`, the
  `UPDATE_ROLLBACK_COMPLETE` stack with 57 resources, and the exact normalized
  baseline hash. The operator role, Lambda resource policy, and pending change
  sets are absent.
- Local candidate comparison removed exactly the dormant permission. Parameter
  selection preserved 18 values. The reduced permission plan contains 10
  requests; IAM simulation allowed all 67 evaluated action-resource pairs.
- The deploy role is denied `iam:GetRole`, `iam:GetRolePolicy`,
  `iam:ListRolePolicies` and `iam:ListAttachedRolePolicies` on the new role, so
  the workflow uses its allowed `iam:SimulatePrincipalPolicy` for the effective
  invoke check. A separate administrator read after execution must inspect
  the live trust and inline policy. AWS `SimulateCustomPolicy` validated the
  proposed identity-only policy's exact allow and deny matrix before Actions.
- Local checks: 566 unit tests passed (5 skipped); `pip-audit` found no known
  vulnerabilities; SAM validated both source and production projection;
  CloudFormation lint, actionlint and `git diff --check` passed.

This local correction has not been pushed or deployed. The failed digest cannot
be reused. A new protected review and its exact native inventory are required
before requesting separate execution approval.
