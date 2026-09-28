# TEST validation separated from private deployment

Date: 2026-09-10 (Central Time)

- TEST source promotion now performs credential-free validation and immutable
  artifact verification only. The exact two-parent dev merge/tree gate remains.
- Both runtime and release suites run before the SAM build. Validation artifacts
  use a distinct name and schema, bind source/run/attempt, and explicitly mark
  themselves nondeployable. They contain no deployment tools.
- Regression tests execute the actual metadata writer/verifiers and prove that
  historical rollback rejects validation artifacts before credentials while
  retaining its original release compatibility.
- New THN provisioning and activation use the separate private lifecycle. This
  avoids an ordinary full-template deployment introducing a partial registry
  before the reviewed five-resource bootstrap. Historical rollback remains a
  separate privileged path for compatible release artifacts.
- Runtime, SAM template, registry bootstrap, private lifecycle, retained-state
  protections and historical rollback implementation are unchanged. No other
  draft or production runtime is changed by this source-flow correction.

This change is not evidence of AWS deployment, private-origin activation,
account enrollment, or live client acceptance.
