# 2026-09-04 THN Content Hub v2 authoring boundary

## Outcome

Implemented the fail-closed TASK-021 request and authorization boundary for the
isolated The Hair Narrative Content Hub v2 artifact without activating TEST or
changing the legacy Content Hub v1 runtime.

## Changes

- Added exact protected read and action allowlists; unknown or ambiguous
  operations stop before any registry, session, user-state, or content access.
- Added exact payload/header scope checks for the THN domain, owner profile, and
  Journal hub.
- Read only the namespaced Auth Admin v2 session and current-user records with
  strongly consistent reads; validate TTLs, revocation, role, immutable account
  purpose, enabled state, and session version.
- Required the namespaced session cookie on every operation and cookie/header/
  stored-hash CSRF agreement on every mutation.
- Validated the exact Lambda context ARN, TEST environment, table names, and
  immutable descriptor, digest, and Auth Admin policy coordinates before using
  AWS dependencies.
- Kept `writerMode=disabled` fail-closed and added the authorized `writerEpoch`
  to the final DynamoDB registry-fenced transaction contract.
- Preserved a controlled `feature_not_ready` response for every authorized
  business operation until the later CRUD, upload, preview, and publication
  tasks implement those behaviors.

## Review finding fixed

The first audit found that a disable/re-enable sequence could restore the same
writer mode while changing `writerEpoch`. The final transaction helper now
requires the exact epoch captured during authorization before it starts the
transaction, and a regression test proves that the stale request performs no
write.

## Verification

- Focused authorization, registry-fence, TASK-019, TASK-020, and TASK-021 tests
  pass.
- The complete Python suite passes with the isolated Windows timezone test
  dependency.
- Basic SAM validation, direct cfn-lint validation, a no-cache nine-function
  SAM build, exact artifact allowlists, standalone authoring-artifact import,
  dependency audit, compilation, and `git diff --check` pass.
- Three audit/fix/re-audit rounds cover request dispatch, session/CSRF/purpose,
  configuration binding, epoch races, IAM separation, artifact isolation, and
  legacy v1 regression.

## Delivery state

No AWS deployment, resource mutation, registry activation, account change,
workflow dispatch, Git commit, push, frontend edit, draft edit, or Zoosite
change was performed. TASK-022 (the separate private Image Upload v2 boundary)
is the next implementation task.
