# THN production Registry operator patch

## Context

The production Hub state release left its Registry mutation Lambda available while the
human operator and Journal routes remain disabled. The next API activation requires a
Registry reservation, and the existing `state`/`activate` purposes cannot safely make
the operator available in that order.

## Change

- Add an `operator-patch` purpose to the retained production release. It uses the
  currently deployed Original template, so it does not rebuild or replace Lambda code.
- Require exactly two parameter changes and retain the other 18 with
  `UsePreviousValue`. The human role is restricted to the reviewed IAM principal and
  requires MFA, including an age limit of 300 seconds.
- Accept only three nonreplacing native additions: the human role, its exact
  invocation policy, and the Lambda invocation permission. Keep the 57 current
  resource identities, protected stack, and closed routes.
- Verify the full baseline and exact operator template before review, repeat the
  guards before execution, and check the resulting 60 resources and Lambda policy.
  The separate administrator read will confirm the live IAM trust after execution.
- Skip SAM build and package in this purpose only. Existing release purposes retain
  their workflow steps and parameters.

## Preflight evidence before GitHub Actions

- AWS account `765932874577`, region `us-east-1`: Hub stack `UPDATE_COMPLETE`,
  termination protected, 57 resources, no available change set. The operator role
  is absent; the Registry mutation Lambda is active and matches its stack resource.
- Both live Original and Processed templates contain the same dormant operator
  definitions with exact MFA trust and invocation scope. Local selection produces
  two explicit values and 18 `UsePreviousValue` entries.
- AWS native schemas require 13 distinct IAM/Lambda handler actions across the
  three additions. The bounded permission plan covers all 13. IAM simulation
  allowed all 70 action-resource pairs in 11 requests, including the deployment
  role's read of the eventual Lambda policy.
- The private release bucket has versioning and all four public-access blocks.
  The GitHub production Environment admits `main` only.
- Read-only recovery rehearsal downloaded all nine active Lambda ZIPs (147,578,755
  bytes total) through their signed code locations and matched every `CodeSha256`.
- The TEST Registry mutation Lambda's existing resource policy confirms the
  response shape expected by the post-execution policy check.
- Local checks: 564 unit tests passed (5 intentionally skipped), 134 release tests
  passed, `pip check`, `pip-audit`, SAM validation, projected-template
  `cfn-lint==1.56.0`, `actionlint`, and `git diff --check` passed.

No production change set or GitHub Action was created during this preflight. The
permission plan must be sealed to the exact future `main` SHA before a protected
review. The native change-set inventory remains a separate review gate and its
digest requires separate authorization before execution.
