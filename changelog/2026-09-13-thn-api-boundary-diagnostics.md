# THN processed API rejection diagnostics

2026-09-13 (Central Time).

- Preserve the specific, closed API rejection reason in the dedicated TEST
  lifecycle error. Unknown exception arguments are not reflected into logs.
- Keep only the identity-verified, unexecuted plan rejected at this Processed API
  boundary for private template inspection. Other cleanup paths remain intact.
- No API comparison, permission, route, deployment source or runtime behavior is
  relaxed. A retained plan is not a service or authorization to execute it.
- Regression coverage exercises actual API drift, actual permission drift,
  unknown exception privacy and unchanged cleanup for unrelated shared drift.

This diagnostic source change does not resolve an unexplained provider-side
template difference or establish that the blog is active. Follow the owning
[TEST lifecycle guide](../docs/thn-test-release.md) for review and cleanup.
