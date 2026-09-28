# Closed THN production source

25 private modules use code-owned production coordinates; sealed private ZIPs include profile+coordinate helper. V1 Lambda unchanged. Shared ContentHubApi retains path set with production alias rebinding. Main source-only selector HUB_PRODUCTION_PROMOTION_SELECTION_JSON prevents credentials on integration.

Offline candidate generator retains private state, leaves provision/activation false, and requires separately confirmed production dependencies. No AWS deployment is performed by the generator.

Verified: 485 runtime (0 skips), 134 release; native SAM translation closed/active and no dangling references; actionlint all workflows; git diff --check; runtime pip-audit with Windows trust store (no TLS bypass), no known vulnerabilities. SAM CLI not installed locally; actual workflow sam validate/build pending.

This source is not deployment-ready by itself. Protected production review/execute/recovery workflows, effective IAM proofs, real production bindings and separate owner enrollment remain required. No TEST data/accounts/credentials are copied.

Production release supports retained native previews, exact digest execution, sealed package and prior-byte recovery, and independent general v1 review. Fresh source authority is checked before credentials and immediately before native changes. IAM simulations evaluate actual action/resource context rather than unrelated whole-policy context. Production operator grants remain closed behind exact human principal, MFA and separately reviewed native inventory; no TEST QA data or credentials are copied.

The protected source promotion now checks the parsed native merge commit
against GITHUB_SHA. This resolves the actual ShellCheck SC2034 unused-variable
failure and explicitly binds the head identity. Actionlint 1.7.12 with the CI
ShellCheck 0.9.0 validates every tracked workflow without suppressing checks.

- Keep the shared production release driver identical across the four services:
  its Auth-only branch explicitly selects Auth's production artifact inventory,
  excluding the TEST QA/owner mediator. Other service inventories and native
  templates are unchanged.
