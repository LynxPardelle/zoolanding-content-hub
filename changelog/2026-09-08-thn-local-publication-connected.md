# THN local publication and public delivery - 2026-09-08 CT

- Connected the exact TEST-only internal gateway, independently authorized
  publisher, immutable preparation, automatic URL allocation and atomic
  publication/withdrawal. No public writes are granted to authoring.
- Added bounded durable invalidation delivery and version-specific orphan
  collection with age, reference, digest and quiet-period fences.
- Retained session condition-only access, independent current-user/registry
  revalidation and transaction-only publication audit writes. Handler/artifact
  boundaries remain separate from v1 and other tenants.
- Verified 445 local tests with the pinned boto3 1.39.13 dependency and actual
  local Runtime Read/public-media consumers. Generated nine allowlisted,
  reproducible candidate ZIPs without deployment.
- SAM lint still reports the same three baseline W1028 warnings; it is not a
  clean lint. No AWS, repository setting, registry, account or writer activation
  was performed. A/B/C release gates remain unsigned.
