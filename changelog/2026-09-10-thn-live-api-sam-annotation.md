# Exact live API SAM annotation

Date: 2026-09-10 (Central Time)

A read-only composition check against the already-provisioned registry baseline
found one non-Body difference: the live API carried exactly
`Metadata: {SamResourceId: ContentHubApi}` and the candidate omitted metadata.
The strict source comparison rejected provisioning before any change set.

The composer now recognizes only that exact live-singleton/candidate-absence
pair. It copies the existing annotation into the temporary comparison object;
the output keeps the entire live API metadata unchanged. All other metadata,
API properties, globals, route contracts and processed-template comparisons
remain strict. Neither source snapshot is modified.

A regression failed before the correction and passed afterward. Negative cases
cover changed identifiers, extra/unknown/empty/null metadata, stage, CORS,
globals and non-allowlisted Body content. Existing retention, resource identity
and exact three-route boundaries remain mandatory.

This source correction changes no runtime, IAM policy, template, workflow,
registry row, AWS resource, other draft or production setting. The accepted
registry baseline remains in place; do not repeat registry bootstrap. Any later
TEST provisioning still needs normal promotion, a fresh immutable private
release artifact and independent live acceptance.
