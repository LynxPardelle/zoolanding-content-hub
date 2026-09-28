# THN TEST parameter selection — 2026-09-07 (Central Time)

Local delivery correction; not deployed or activated.

- Replaced hard-coded v2-only disabled values with an optional, complete,
  closed TEST selection. Omission retains the prior parameter map exactly.
- Rejected unknown/shared fields, wrong environment/account/role, invalid
  identifiers, duplicate JSON keys, incomplete activation, and oversized input.
- Kept runtime enablement separate from retained-state provisioning. Activation
  and provisioning check the real TEST stack's termination protection; the
  preflight does not alter cloud state.
- Wired the same validator into deploy and rollback before change-set creation,
  without changing workflow triggers, permissions, v1 parameters, runtime code,
  resource definitions, or any draft payload.

Existing rollback artifacts lacking this new selector/preflight are not
compatible merely because their old source tests passed. Recovery selection,
business CRUD/publishing, owner onboarding, and full TEST activation remain
separate completion requirements.
A supplied selection now requires a packaged-tool capability check before
credentials; a legacy artifact is rejected instead of silently ignoring it.
Disabling an existing conditional runtime remains blocked by the unchanged
no-removal guard and requires a separately reviewed recovery transition.

Verification is recorded in the ignored hub workspace evidence rather than
copying operational values here. No claim of live activation is made.
