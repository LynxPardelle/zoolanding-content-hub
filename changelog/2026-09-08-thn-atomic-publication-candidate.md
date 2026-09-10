# THN atomic publication candidate

2026-09-08 11:35 CT. Local candidate only; uncommitted and not deployed.

- Implemented the injected final publication/unpublication adapter. One bounded
  conditional transaction combines article and public projections, fresh
  authority, image references, path reservations, preparation state, linked
  withdrawal manifest, durable invalidation outbox and redacted audit/receipt.
- Added private automatic URL allocation before immutable preparation. Title
  collisions select a numbered variant; retries retain the chosen URL/dates.
  Unpublication preserves private work and the reserved URL.
- Fenced unchanged sibling-locale public rows and live no-op checkpoints.
  Denied malformed replay results, missing head pages, backward authority time
  and registry metadata-table mismatches.
- Completed three local review/retest rounds: 402, 407 and finally 414 passing
  Content Hub tests, without skips, using the approved local Runtime Read source.
  Coverage includes actual local reader/media consumers, concurrent edits and
  collector races, revoked authority, lost-success retries, two locales and
  atomic replacement of a cover plus twenty inline images.
- The local atomic fixture evaluates conditions before committing any row and
  validates the request shape against the installed SDK service model. This is
  not an AWS transaction or a deployed end-to-end acceptance result.

No rendered route, frontend/draft, Runtime Read, IMAGE service, IAM or Lambda
packaging changed in this increment. No AWS call, deployment, account/registry
activation, GitHub write or other-draft mutation occurred. No new browser QA was
required. Existing SAM warnings were not rerun or reclassified as passing.

The publisher and gateway are not connected to these adapters; Publish stays
disabled. Local permission/artifact integration, invalidation and orphan workers,
public-page wiring/QA and environment acceptance remain pending. A/B/C remain
unsigned. Do not represent this increment as a ready or activated client blog.
