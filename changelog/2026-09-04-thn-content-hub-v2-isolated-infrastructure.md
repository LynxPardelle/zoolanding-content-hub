# 2026-09-04 THN Content Hub v2 isolated infrastructure

## Outcome

Added the build-only, TEST-only infrastructure boundary for The Hair Narrative
Content Hub v2 without changing the legacy generic Content Hub runtime.

## Changes

- Added independent default-off state provisioning and runtime activation gates.
- Added a deployment-workflow termination-protection guard and TEST-only rules.
- Added retained/PITR/encrypted private metadata and audit tables plus a retained,
  encrypted, versioned, block-public-access private bucket.
- Added seven separate Lambda function/role pairs for authoring, private-asset
  collection, publication, public media, invalidation, emergency withdrawal, and
  prepared-orphan collection.
- Kept only authoring and public media on their exact v2 routes; all other v2
  functions have no API route, and all three schedules are disabled.
- Limited each role to exact THN TEST tables, partition keys, object prefixes,
  function ARNs, and the configured TEST CloudFront distribution.
- Replaced three impossible IAM role names (longer than AWS's 64-character
  limit) with short stable physical names and updated the registry allowlists.
- Added conditional outputs for the private state and the activation-critical
  function ARNs.

## Verification

- Contract test was observed failing before implementation and then passing.
- `188` Python unit tests pass when Windows Python is pointed at the trusted Git
  for Windows IANA timezone database.
- Basic `sam validate --region us-east-1` passes.
- `cfn-lint` passes with only `W1028` ignored; that warning is emitted by SAM's
  generated `AutoPublishAlias` condition branches, not by a handwritten
  unreachable branch.
- `sam build --region us-east-1` succeeds for all legacy and v2 functions.

## Delivery state

No AWS deployment, registry activation, Git commit, or push was performed. The
subsequent handler-isolation work is recorded separately; both v2 switches must
stay at their default `false` values until the behavior and activation gates are
complete.
