# 2026-09-07 CT - Private desk lifecycle and public projection candidate

- Working image references now update atomically with the article, its
  concurrency token and the final registry/current-user/session fences.
  Published references cannot be changed through the private editor.
- Successful article edits and completed uploads append safe durable audit
  events in the same transaction. Events exclude text, image pointers and raw
  actor identity.
- Implemented bounded private image collection: exact candidates only, no
  untracked/referenced/live/recent images, conditional claim before deletion,
  and exact immutable version deletion. The role is limited to article checks,
  asset updates and the dedicated private-upload object prefix. The schedule
  remains disabled; an approved candidate source is still required.
- Added pure, closed public index/path/category/bundle/media-manifest builders
  and local compatibility tests. Bundles preserve public focal coordinates and
  sanitized body variables without leaking private tags, Delta or ownership.
  The publisher entrypoint remains fenced: these helpers alone publish nothing.
- No deployment, activation, account/registry change, GitHub write, or change to
  other draft data was performed. This is an uncommitted local candidate, not a
  signed B/C release. Public publisher/outbox/orphan integration and public
  Journal page wiring are still outstanding.
