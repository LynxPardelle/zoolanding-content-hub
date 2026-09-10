# THN private publication preparation - 2026-09-08 (Central Time)

Local implementation only; no AWS calls, IAM updates, deployment, publication,
account changes or other-draft changes.

- With explicit user approval, added a condition-only final-session permission
  to the candidate THN publisher role. The session table cannot be read, listed
  or mutated, and conditional failures must not return its attributes.
- Extracted the existing actor/session checks into a pure shared module,
  tightened malformed authority validation, and included it in the private
  authoring artifact. Updated the two prior blanket-denial tests to verify the
  exact approved exception while preserving other auth/tenant exclusions.
- Added private immutable preparation orchestration: fully scoped ready-image
  metadata, exact versioned keys and digests, generated sanitized bundles,
  restartable exact-key cleanup intents and versioned receipts. Storage failure
  never installs a live delivery manifest or changes an existing publication.
- Ran test-first negative cases and three audit/retest rounds. The complete
  backend suite passes 368 tests with the explicit local Runtime Read candidate.

Still pending: the production preparation adapter, final publication and
unpublication transactions, publisher/gateway, invalidation/orphan completion,
public Journal wiring, immutable release and environment activation. The new
preparation code is not packaged in the dormant publisher artifact. No gate is
signed and Publish must remain disabled.
