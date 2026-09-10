# 2026-09-04 THN Content Hub v2 handler isolation

## Outcome

Added the seven distinct THN Content Hub v2 entrypoints and exact Lambda
artifact boundaries without activating their unfinished behavior or changing
legacy v1 dispatch.

## Changes

- Kept v2 authoring in `lambda_function.py` under its own entrypoint.
- Added separate modules for private-asset collection, publication, public
  media, invalidation, emergency withdrawal, and prepared-orphan collection.
- Made every unfinished internal handler fail before reading configuration or
  creating an AWS client; unfinished HTTP handlers return a generic no-store
  `503` response.
- Added a custom SAM make build for all nine Lambda functions in the template,
  including the legacy Content Hub and registry mutation function.
- Added an exact source allowlist and post-build validator for each artifact so
  project files cannot cross function or v1/v2 boundaries.
- Preserved the pinned runtime dependency installation only for the three
  functions that currently consume the AWS SDK.

## Verification

- The focused TASK-020 test was observed failing before implementation and then
  passing.
- The complete Python suite passes, including existing v1 behavior tests.
- All source-only artifacts import their declared handler in isolated child
  processes.
- A clean SAM build produced nine artifacts; all nine pass the exact artifact
  validator, and the built template passes basic SAM validation.
- Python compilation, direct cfn-lint validation, and `git diff --check` pass.

## Delivery state

No AWS deployment, resource mutation, workflow activation, Git commit, push,
frontend edit, draft edit, or Zoosite change was performed. The v2 gates remain
default-off; the subsequent TASK-021 authorization boundary is recorded in its
own changelog entry and still does not activate owner authoring.
