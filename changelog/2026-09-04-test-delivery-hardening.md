# 2026-09-04 TEST delivery and immutable rollback hardening

- Replaced the permissive TEST deployment path with exact `dev`-to-`test` promotion, unprivileged validation/build, commit-pinned actions, and OIDC only in the protected `test` environment job.
- Added full-SHA and exact full-inventory artifact verification, runtime-configuration validation before credentials, and a live-state guard that keeps ordinary Content Hub v2 provisioning and activation disabled.
- Added fail-closed change-set review, stack/Lambda readiness smoke checks, immutable rollback coordinates, and manual rollback from one successful recorded TEST artifact.
- Verification passed with 261 tests, Actionlint, Python and Bash syntax checks, scoped CloudFormation lint, dependency audit, and diff validation. No workflow was dispatched and no AWS, production, frontend, draft, or Zoosite state changed.
