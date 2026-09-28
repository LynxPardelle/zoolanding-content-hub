# TEST change-set response compatibility

Date: 2026-09-08 (Central Time)

- Corrected the TEST change-set reviewer to accept AWS `DescribeChangeSet`
  responses that omit `ChangeSetType`. Creation still binds the type; exact ARN,
  name, stack, parameters, status, no-removal and no-replacement guards remain.
- Added realistic create, update, no-op, optional-field, identity-drift and runner
  binding regressions. The focused suite failed before the correction and passes
  afterwards.
- Reconciled the three bundled SAM W1028 warnings with the unchanged source:
  the older translator generates repeated conditions at the HTTP path, method
  and integration URI. Documented the already-pinned cfn-lint 1.56.0 command;
  no resource semantics or lint suppression changed.
- This is local verification only. It does not establish a retained-runtime
  disable path, sign a release gate, deploy, activate or change production.
