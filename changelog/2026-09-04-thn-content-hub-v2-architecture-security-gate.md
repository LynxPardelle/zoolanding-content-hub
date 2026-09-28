# 2026-09-04 THN Content Hub v2 architecture security gate

## Outcome

Completed the local, build-only TASK-025 SAM/IAM/recovery isolation gate for
The Hair Narrative. No TEST or production resource was deployed or activated.

## Changes

- Added one consolidated policy suite covering the seven distinct v2 function
  and IAM-role pairs, closed route inventory, private/public boundaries,
  worker and collector limits, emergency isolation, and retained TEST state.
- Narrowed the publisher's private S3 read from the whole THN hub prefix to
  only immutable revision packages at
  `immutable-revisions/{articleId}/{locale}/{revisionId}/package.json`.
- Proved authoring has no public projection access; public media is read-only;
  collectors cannot list or derive keys; invalidation cannot write content;
  emergency withdrawal cannot access Zoosite, private storage, or auth state.
- Kept every non-public worker route absent or disabled and preserved all v1
  Content Hub resources and behavior.

## Delivery state

Provisioning and activation remain default-off. No AWS call, workflow dispatch,
Git commit/push, frontend or draft edit, or Zoosite mutation was performed.
TASK-026 is the next Workstream A task. Publisher behavior remains owned by the
later public-delivery Workstream C and was not implemented here.
