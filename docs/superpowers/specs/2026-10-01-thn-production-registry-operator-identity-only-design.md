# THN production Registry operator: identity-only correction

Date: 2026-10-01

## Failure and verified state

The approved `operator-patch` review `36816877481` produced three `Add` actions and digest
`c874782346dc7958035d53789bcf91e80354a7d2b9ac74bbfbf35b7aabb132f9`.
Execution `36817290193` failed while CloudFormation created the IAM role and Lambda
permission concurrently. Lambda rejected the permission because its role principal
was not yet valid. The permission's ARN was built from account pseudo parameters,
so CloudFormation had no dependency on the new role. The failed digest cannot be
reused.

CloudFormation finished `UPDATE_ROLLBACK_COMPLETE`. The stack remains protected
with the original 57 resources. The operator role and Lambda policy are absent.
The current full baseline, after normalizing only stack status to
`UPDATE_COMPLETE`, hashes to the prior review baseline
`06d5ee8e96c46ccd9e5a52d6305289829075eb8867d2fa95e76ca43c3472efb8`.
There is no retained resource to import or delete.

## Decision and scope

Use the existing same-account IAM policy as the sole Lambda invocation grant.
That policy permits only `lambda:InvokeFunction` on
`zoolanding-content-hub-prod-ThnServiceBindingRegistryV2Mutation`. Keep the
human operator role's exact IAM principal and MFA trust, including the 300-second
MFA age limit. AWS documents identity-based Lambda access for roles in the same
account; a Lambda resource-based grant is not required for this direct invocation.
See [AWS Lambda permissions](https://docs.aws.amazon.com/lambda/latest/dg/lambda-permissions.html)
and [CloudFormation dependency ordering](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-dependson.html).

Remove `ServiceBindingRegistryOperatorInvokePermission` only from the production
projection and the one-time production `operator-patch` candidate. The TEST
template and TEST operator stay as they are. Do not alter the mutation Lambda,
Registry table or policy, public routes, writer mode, QA account, or articles.

## Release guard

- Accept `UPDATE_ROLLBACK_COMPLETE` as the starting status only when the full
  captured baseline, with that one status field normalized to `UPDATE_COMPLETE`,
  equals the reviewed hash above. Continue to require 57 expected resources,
  termination protection, exact dormant role and IAM policy definitions, closed
  routes, original parameters, absent operator role, and absent operator Lambda
  policy.
- Build the candidate from the deployed Original template. Remove exactly the
  dormant production `ServiceBindingRegistryOperatorInvokePermission` definition;
  preserve every other template node. Select the same two parameter changes and
  preserve the other 18 values.
- Reject any change set unless it has exactly two nonreplacing native `Add`
  actions: `ThnProductionRegistryHumanOperatorRole` (`AWS::IAM::Role`) and
  `ServiceBindingRegistryOperatorInvokePolicy` (`AWS::IAM::Policy`). The policy's
  `Ref` to the role provides CloudFormation's creation dependency. Reject extra
  actions, changed existing identities, unexpected template differences, or
  changes to Lambda's resource policy.
- After execution, require `UPDATE_COMPLETE`, 59 stack resources, all 57 prior
  logical and physical identities unchanged, the exact new role and IAM policy,
  the approved parameter values, unchanged Lambda resource policy, and the exact
  MFA trust and identity-based invoke scope.

## Validation and release sequence

Add focused tests for the observed failure mode: no production Lambda
permission, the two-resource inventory, preserved 18 parameters, exact
rollback-baseline exception, and post-execution identity and policy checks.
Run the full local unit/release suites, dependency audit, SAM validation,
CloudFormation lint, actionlint, and a read-only AWS comparison before the first
GitHub Action. Simulate the reduced permission plan against the real IAM roles.

Promote the correction through `dev`, `test`, and `main` as source only with the
normal checks and exact selectors. Do not trigger the old failed change set.
Update the production permission-plan secret to the new MAIN SHA only after
review. Run a new protected `operator-patch` review and inspect its native
inventory and digest. Request separate authorization for the new digest before
execution. If any guard or stack update fails, inspect CloudFormation events,
stack resources, IAM role, and Lambda policy before another run.
