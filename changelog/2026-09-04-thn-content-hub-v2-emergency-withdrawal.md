# 2026-09-04 THN Content Hub v2 emergency withdrawal

## Outcome

Implemented the build-only TASK-024 emergency-withdrawal boundary for The Hair
Narrative without activating TEST or changing the legacy Content Hub v1 runtime.

## Changes

- Added a closed THN-only projection-manifest contract with complete schemas,
  SHA-256 page digests, page/count/state invariants, unique exact public
  pointers, and a maximum of 19 deletions per manifest page.
- Implemented the direct-IAM-only emergency handler with an exact three-field
  event, exact `test` alias check, strongly consistent binding, manifest, page,
  and checkpoint reads, and generic errors.
- Require the service binding to be active with `writerMode=disabled` at the
  requested monotonic writer epoch, then condition-check that same complete
  binding inside every public deletion transaction.
- Delete only public article, EN/ES locale-path, category/index, and live-media
  pointers recorded by the sealed manifest. Each absent-or-exact condition is
  bound to THN scope and the recorded immutable bundle or revision identity.
- Atomically advance one manifest page, consume that exact page, checkpoint the
  batch, remove its pointers, enqueue targeted invalidations, and append audit
  evidence in at most 25 DynamoDB transaction items.
- Added deterministic resume and idempotency behavior, including a complete
  empty-manifest path, without querying, scanning, reading S3, or mutating
  private authoring data.
- Bound both the named operator's identity policy and Lambda resource permission
  to the SAM-generated `test` alias; no public or scheduled invocation exists.
- Added the projection dependency to the emergency artifact's exact source
  allowlist while preserving all other function boundaries.

## Review findings fixed

The first audit added impossible-count rejection, adapter-side reconstruction
of every batch before AWS access, and immutable bundle identity on article
deletes. The second audit replaced a CloudFormation resource type unavailable
in the target regional specification, referenced the SAM-generated alias to
avoid creation-order drift, and added the complete `livePointers` page
condition. The third audit re-ran all runtime, IAM, artifact, regression, and
dependency checks and found no remaining reportable issue.

## Verification

- Eighteen focused emergency-withdrawal tests and all 245 repository tests pass.
- Ruff lint/format, Python compilation, dependency audit, source cfn-lint,
  basic SAM validation, and `git diff --check` pass.
- A fresh no-cache SAM build produced all nine functions; every exact artifact
  allowlist, the built template, and the built emergency import smoke pass.
- Three audit/fix/re-audit rounds cover invocation, writer fencing, manifest
  integrity, deletion identity, bounded transactions, resumability,
  invalidation/audit durability, error disclosure, IAM, v1 regression, and
  cross-draft isolation.
- The TASK-024 security contract is sealed with complete coverage, eight
  reviewed surfaces, zero reportable findings, and four verified artifact
  hashes.

## Delivery state

No AWS deployment, resource or registry mutation, writer activation, workflow
dispatch, Git commit, push, frontend edit, draft edit, or Zoosite change was
performed. Content Hub v2 provisioning and activation remain disabled by
default. TASK-025 is the consolidated SAM/IAM/recovery isolation gate. The
publisher must later create the sealed projection manifest in Workstream C
before the emergency path can be activated or rehearsed end to end.

Live account IAM inventory, publisher-generated manifest completeness,
CloudFront invalidation draining, and rollback convergence were not exercised
and remain activation-time checks.
