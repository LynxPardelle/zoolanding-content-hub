# 2026-09-07 CT - THN offline private-media integration

- Connected the v2 authoring upload action to an exact-key, IAM-only private
  processor. Source data never uses the shared public uploader.
- Bound upload transactions to purpose, epoch, article, locale, revision and
  image digest. Final private asset writes additionally recheck the current
  user/session and article concurrency token atomically.
- Added single-asset protected preview reads and inert inline-image placeholders;
  browser previews do not create public URLs. Private records pin S3 versions.
- Added local scope/epoch/revocation/retry/limits/integrity and HTTP tests.
  Cross-repository verification uses synthetic pixels and memory-only storage.
- Updated only the dedicated authoring role's exact image transaction partition,
  image TEST alias and private version-read prefix. No scan, list, public-store,
  other-draft or legacy v1 grants were added.
- No cloud resources, registry settings, accounts, repository settings, workflow
  runs or published drafts changed. The actual desk, audit/media lifecycle and
  publisher remain unfinished; this entry does not sign Workstream B or C.
