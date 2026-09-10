# THN preparation adapter and projection integrity

2026-09-08 11:17 CT. Local candidate only; uncommitted and not deployed.

- Added the injected SDK preparation adapter: exact private source versions,
  create-only delivery-ready objects, digest validation, fenced intent/receipt
  writes, retry recovery and original orphan-candidate age preservation.
- Added pure bilingual projection transitions. An update records every expected
  prior row and exact replacement/removal; it cannot make public writes itself.
- Fixed producer/withdrawal contract drift: public storage rows now include the
  internal identity markers required by existing conditional withdrawal. The
  actual local Runtime Read candidate excludes these markers from responses.
- Included Home in the THN invalidation inventory, alongside Journal, detail,
  series, sitemap, search and exact affected media paths.
- Completed three local review/retest rounds. Final Content Hub suite: 390 tests,
  zero failures and zero skips with the approved local Runtime Read candidate.
  The lifecycle test applies pure transitions to synthetic rows; it is not an
  AWS transaction or deployed integration test.

No frontend/draft, shared runtime, IAM, AWS, GitHub settings, credentials or live
content changed in this increment. Earlier candidate changes remain untouched.
No new browser QA was required because no rendered route changed in this work.

The adapter is not packaged/wired/enabled for the dormant publisher. Final atomic
private/public publication, fresh-authority publisher invocation, gateway,
invalidation worker, orphan collector, public-page data integration and deployment
acceptance remain pending. Do not enable Publish or sign Workstream C from these
tests alone. Existing SAM warnings were not changed or reclassified as passing.
