# 2026-09-04 THN Content Hub v2 public media

## Outcome

Implemented the build-only TASK-023 public-media origin for The Hair Narrative
without activating TEST or changing the legacy Content Hub v1 runtime.

## Changes

- Added the exact public `GET` media contract with strict method, host, query,
  path-parameter, locale, revision, asset, and variant validation.
- Resolve each request through one strongly consistent read of the exclusive
  `LIVE_MEDIA#test#thehairnarrative.com#thehairnarrative-com-journal#...`
  partition and the exact `MANIFEST#V1` record.
- Accept only an exact THN `published`, `public`, and `live` manifest whose
  canonical media key, non-null S3 version, MIME type, byte length, and SHA-256
  digest agree with the requested immutable variant.
- Fetch only that S3 object version, reject encoded or inconsistent responses,
  enforce a four-MiB raw limit that remains below Lambda's buffered-response
  ceiling after Base64 expansion, recheck length and digest, and emit `nosniff`
  plus one-year immutable cache headers.
- Restrict the public-media execution role to one live-manifest namespace and
  `s3:GetObjectVersion` on the THN public media prefix. It has no list, write,
  delete, authoring-state, registry, private-store, unversioned-read, or Zoosite
  permission.
- Package the public-media artifact with its pinned AWS SDK dependency while
  preserving the exact per-function source allowlist.

## Review findings fixed

The first audit narrowed the manifest partition, public-host precondition, and
IAM permissions to their exact THN live-delivery contracts. The second audit
added explicit rejection of unexpected S3 content encoding and a regression
proving that runtime failures produce only a generic no-store response. The
third audit rejected duplicated or port-suffixed forwarded hosts and lowered the
raw object ceiling so the Base64 proxy response stays within Lambda's buffered
synchronous-response quota.

## Verification

- Ten public-media tests, 29 focused boundary tests, and the complete 227-test
  Python suite pass.
- Python compilation, Ruff lint/format, dependency audit, source cfn-lint,
  built-template SAM validation, a clean no-cache nine-function SAM build, all
  nine exact artifact checks, standalone built-handler import, and
  `git diff --check` pass.
- Direct cfn-lint reports only the three previously documented SAM-generated
  W1028 unreachable false branches for condition-gated HTTP API events; the
  source template has no other lint finding.
- Three audit/fix/re-audit rounds cover request parsing, live-manifest schema,
  immutable version selection, S3 response integrity, error disclosure, IAM,
  packaging, v1 regression, and Zoosite isolation.

## Delivery state

No AWS deployment, resource mutation, registry activation, workflow dispatch,
Git commit, push, frontend edit, draft edit, or Zoosite change was performed.
The Content Hub v2 provisioning and activation switches remain disabled by
default. TASK-024, emergency withdrawal, is the next architecture task.

Live front-door header provenance and deployed AWS behavior were not exercised
in this build-only task and remain activation-time checks.
