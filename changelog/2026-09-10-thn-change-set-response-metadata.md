# THN change-set response metadata

Date: 2026-09-10 (Central Time).

The registry bootstrap's final review compared entire SDK `DescribeChangeSet`
responses. Per-request metadata could differ even when the complete change-set
payload was unchanged, causing a false `registry_bootstrap_changed_during_review`
rejection before execution.

The comparison now excludes only top-level `ResponseMetadata` from each response
without mutating either. All other fields, including unknown keys and nested
metadata-named fields, remain in the comparison. No IAM, template, workflow,
HTTP route, resource allowlist, lifecycle or other-draft behavior changed.

An SDK-shaped runner regression failed before the correction. It varies request
IDs, HTTP headers and retry counts, then requires the exact 17 preserved plus
five new resources and two retained-state checks. Negative cases require genuine
identity, status, parameter, resource or unknown-field changes on the second read
to reject before execution and clean only the runner's own unexecuted change set.

This source correction is not deployment or blog-activation evidence. The private
TEST workflow still requires a fresh source-bound artifact and complete live
baseline checks. See the [retained lifecycle contract](../docs/thn-test-release.md).

Validation: three complete audit rounds passed 462 runtime tests and 84 release
tests each, with no skips. Actionlint, cfn-lint, dependency consistency and the
dependency vulnerability audit passed. The audit reported an unreadable cache
entry but completed successfully without known vulnerabilities. No browser QA
was required because no rendered behavior changed.
