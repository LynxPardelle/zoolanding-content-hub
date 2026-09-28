# 2026-09-07 — THN offline private-editor candidate

Date: 2026-09-07, Central Time. Not deployed, published, activated or release-ready.

The user authorized local editor/publication preparation before deployment
preparation is signed. This changes ordering only, not security or release gates.

- Added the fixed bilingual package/Delta model and private article service.
- Added immutable package storage with integrity checks and atomic private
  metadata CAS plus registry/current-user/session conditions.
- Wired create, save, list, detail, taxonomy, asset metadata, validate and private
  preview through the existing isolated v2 authoring boundary.
- Added create/save replay protection, QA retention metadata and shared-series
  consistency. Duplicate JSON keys and non-finite numbers are rejected early.
- Extended only the isolated authoring source allowlist and narrowly scoped
  version-read/actor-condition permissions. The v1 artifact remains unchanged.
- Exercised the frozen Runtime Read contract locally and found missing-locale
  leakage. Public delivery remains blocked pending revised scope; the expected
  failure is recorded explicitly, not counted as passed compatibility.

Private editor/service/store/HTTP tests, full service regression tests and source
artifact compilation were run locally. The full service suite contains one known
expected failure for the frozen-reader mismatch. This is not browser QA, a full
reproducible deployment artifact, or evidence of live activation.

Remaining integration includes the generic Angular desk, private-origin/SSR
binding, upload transactions/media/reference lifecycle, durable audit, publisher
and responsive end-to-end acceptance. Public publication actions remain fenced.
