# THN registry IAM action correction

Date: 2026-09-10 (Central Time).

DynamoDB rejected the registry table resource policy because three API names
were used as IAM actions. The correction removes those invalid Action entries,
keeps the existing unconditional PartiQL denials, and explicitly denies
transactional reads through GetItem plus EnclosingOperation=TransactGetItems.
Ordinary approved reads keep their existing principal/partition constraints.

No allow statement, deployment identity grant, mutation execution role,
resource name, retention setting, workflow, HTTP route or other draft changes.
The correction is confined to the TEST registry table policy and its contracts.

Three new regression tests first produced four expected failures against the
old policy. They require the reviewed IAM action set, an exact unconditional-
principal transactional GetItem deny, and unchanged unconditional PartiQL/batch
denials. The existing textual test now checks the valid transaction condition
instead of requiring an invalid IAM action.

Three complete validation rounds passed: 462 runtime tests and 87 release
tests per round, actionlint, pinned cfn-lint, SAM validation and diff checks.
Dependency validation and audit found no broken requirements or known
vulnerabilities. A read-only IAM custom-policy simulation passed 24 decisions
against the changed deny blocks with synthetic identities and an allow-control
fixture; this is not proof of effective access for a deployed role. Full-template
comparison confirmed that no other template properties or allow statements
changed. Read-only live composition preserved all 17 existing resources and
included exactly the five intended registry resources, with no HTTP additions.

Source validation and publication do not establish successful provisioning or
blog activation. The separate private TEST workflow still owns registry-only
execution, immutable artifacts, exact resource accounting and retained-state
verification. See the [retained lifecycle contract](../docs/thn-test-release.md).
