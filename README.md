# Zoolanding Content Hub

<!-- zoolanding-hub-routing:start -->
## Zoolanding Knowledge Router

Shared procedures are routed through the Zoolandingpage hub. Start with [AGENTS.md](AGENTS.md) and open only the document needed for the current task.

| Task | Read |
| --- | --- |
| Article package contract | [docs/api-driven-config/18-content-hub-article-packages.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/18-content-hub-article-packages.md) |
| Protected feature contract | [docs/api-driven-config/19-protected-feature-contract.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/19-protected-feature-contract.md) |
| Draft lifecycle and publication | [docs/11-draft-lifecycle.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/11-draft-lifecycle.md) |
| Fleet ownership | [docs/repository-map.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/repository-map.md) |

Critical repository-specific safety, deployment, and rollback rules remain local.
<!-- zoolanding-hub-routing:end -->

Generic serverless BFF for Zoolanding content hub reads and authoring mutations.

It supports draft-configurable blog/content workflows without putting storage, policy, or authorization material in public `site-config.json`.

## Repository Guide

- Read [AGENTS.md](AGENTS.md) first, then open only the files its task router identifies.
- Runtime, lifecycle, and authorization live in [lambda_function.py](lambda_function.py), with contract coverage in [tests/test_content_hub_handler.py](tests/test_content_hub_handler.py).
- Infrastructure and release behavior live in [template.yaml](template.yaml), [samconfig.toml](samconfig.toml), and [.github/workflows/](.github/workflows/).
- Historical implementation and release evidence is opt-in under [changelog/](changelog/); [Codex.md](Codex.md) remains only a compatibility pointer.
- Cross-repository ownership is defined by the canonical hub [documentation index](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/README.md), [repository map](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/repository-map.md), [article-package contract](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/18-content-hub-article-packages.md), and [protected-feature contract](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/19-protected-feature-contract.md).

## Endpoints

- `POST /features/content-hub/read`
- `POST /features/content-hub/action`
- `POST /features/content-hub/public-action`
- `OPTIONS /features/content-hub/read`
- `OPTIONS /features/content-hub/action`
- `OPTIONS /features/content-hub/public-action`

The browser sends:

- `X-ZLP-Domain`
- `X-ZLP-Auth-Profile-Id`
- `X-ZLP-Content-Hub-Id`
- `X-ZLP-CSRF` for mutations
- auth-admin cookies created by `zoolanding-auth-admin`

`public-action` is only for public visitor interactions. It does not use auth-admin
cookies, but it still requires an allowed origin, a real published public article,
an enabled interaction policy for the requested event type, and rate-limit
admission before writing an interaction row.

## Supported Reads

- `articleList`
- `articleDetail`
- `taxonomyList`
- `moderationQueue`
- `assetList`
- `revisionList`
- `publicBundlePreview`
- `scheduleList`
- `analyticsSummary`

## Supported Actions

- `createArticle`
- `upsertTaxonomy`
- `updatePackage`
- `uploadAsset`
- `validate`
- `submitReview`
- `approveArticle`
- `publish`
- `unpublishArticle`
- `archiveArticle`
- `schedule`
- `cancelSchedule`
- `queueComment`
- `moderateComment`
- `recordInteraction`
- `restoreRevision`

## Authorization

The content-hub config may define `contentHubs[].rolePolicies` with explicit `roleId`, `groups`, and three-part permissions such as `blog:article:update`.

When `rolePolicies` is present, it is the server-side source of truth for every read and action. The older `roles.read/edit/publish/media/moderate` shape remains a compatibility fallback only for configs that do not yet define `rolePolicies`.

Wildcard permissions such as `blog:article:*` are rejected during config normalization. Config errors return only the generic browser-safe message `Content hub service is temporarily unavailable`.

## Action Audit Trail

Protected actions write compact JSON audit events to the existing private, encrypted, versioned packages bucket under `content-hubs/{environment}/{hubId}/audit/{yyyy-mm-dd}/...`.

Audit entries include only operationally safe fields: request id, timestamp, environment, domain, auth profile id, hub id, action, decision/status, status code, hashed actor, and allowlisted target ids such as `articleId`, `revisionId`, `taxonomyId`, `assetId`, `commentId`, `interactionId`, or `scheduleId`.

They must not include cookies, CSRF values, tokens, raw claims, raw roles/groups, request bodies, uploaded file contents, comment bodies, email/phone values, table names, bucket names, signed URLs, or server policy.

This is an operational audit trail using the existing versioned S3 bucket. It is not compliance-grade immutable retention because the bucket does not currently use S3 Object Lock.

## Blog Safety Notes

- `createArticle`, `articleList`, and `articleDetail` carry public-safe SEO, category, tags, comment policy, content safety, canonical, and path metadata.
- `articleDetail` also returns the latest sanitized editable package fields `articleContent`, `components`, `variables`, and `i18n` so draft builders can hydrate article editors without exposing S3 object keys or server-only policy.
- `upsertTaxonomy` stores category/tag administration metadata in DynamoDB and returns only safe taxonomy summaries.
- `publish` requires the article to be approved first, then writes public bundles with SEO, taxonomy, analytics context, comment policy, canonical mode, and safe article path fields.
- `unpublishArticle` and `archiveArticle` mark article metadata private and remove the public slug index without deleting immutable bundles or revision history.
- `schedule` requires an existing article, validates `publishAt`/`unpublishAt` plus `timezone`, and stores the immutable existing revision only for scheduled publishes. Scheduled publish actions require the article to be approved before the schedule can be stored.
- `scheduleList` returns schedule summaries for the authenticated hub, optionally filtered by article, and `cancelSchedule` removes a pending schedule without exposing storage details.
- The SAM schedule event runs due publish/unpublish items every 5 minutes. A bad schedule row records `lastError` on that row without stopping the rest of the due batch.
- DynamoDB-backed list reads page through all query pages internally instead of silently truncating at the first 200 metadata rows.
- `revisionList` and `restoreRevision` require safe existing article/revision ids and never return actor identifiers or storage keys to the browser.
- `queueComment` remains protected, authenticated, and CSRF-checked. `recordInteraction` is also available through the narrow `public-action` route only after its origin, article, event policy, and rate-limit checks; that route never accepts comments or forms.
- `moderateComment` requires an existing queued moderation record and replaces the prior status row for that comment, preserving the safe preview without duplicating queue entries.
- Interaction metadata rejects private fields and obvious email/phone values. Comment queue previews redact obvious email and phone values and do not return raw private contact data.

## Deploy

This repo follows the Zoolanding promotion graph:

- `dev` deploys development.
- `test` deploys testing, only from a merge from `dev`.
- `main` deploys production, only from a merge from `test`.

Required GitHub environment inputs:

- `CONTENT_HUB_CONFIG_JSON_BASE64` secret: server-only compact JSON policy. It must not contain credentials or secret references, and its value must never be copied or logged.
- `AUTH_SESSION_TABLE_NAME` variable.
- `AUTH_USER_STATE_TABLE_NAME` variable.
- `AWS_ROLE_ARN` variable.
- `AWS_REGION` variable, default `us-east-1`.

The Lambda defaults to 512 MB through the `FunctionMemorySize` SAM parameter. This gives more CPU to the cold read path that loads AWS SDK/DynamoDB clients while keeping the runtime configurable per environment.

## Local Tests

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -p "test_*.py"
sam validate
pip-audit -r requirements.txt
```
