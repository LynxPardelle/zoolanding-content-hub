# Zoolanding Content Hub

Generic serverless BFF for Zoolanding content hub reads and authoring mutations.

It supports draft-configurable blog/content workflows without putting storage, policy, or authorization material in public `site-config.json`.

## Endpoints

- `POST /features/content-hub/read`
- `POST /features/content-hub/action`
- `OPTIONS /features/content-hub/read`
- `OPTIONS /features/content-hub/action`

The browser sends:

- `X-ZLP-Domain`
- `X-ZLP-Auth-Profile-Id`
- `X-ZLP-Content-Hub-Id`
- `X-ZLP-CSRF` for mutations
- auth-admin cookies created by `zoolanding-auth-admin`

## Supported Reads

- `articleList`
- `articleDetail`
- `taxonomyList`
- `moderationQueue`
- `assetList`
- `revisionList`
- `publicBundlePreview`

## Supported Actions

- `createArticle`
- `upsertTaxonomy`
- `updatePackage`
- `uploadAsset`
- `validate`
- `submitReview`
- `publish`
- `schedule`
- `queueComment`
- `moderateComment`
- `recordInteraction`
- `restoreRevision`

## Authorization

The content-hub config may define `contentHubs[].rolePolicies` with explicit `roleId`, `groups`, and three-part permissions such as `blog:article:update`.

When `rolePolicies` is present, it is the server-side source of truth for every read and action. The older `roles.read/edit/publish/media/moderate` shape remains a compatibility fallback only for configs that do not yet define `rolePolicies`.

Wildcard permissions such as `blog:article:*` are rejected during config normalization. Config errors return only the generic browser-safe message `Content hub config is invalid`.

## Blog MVP Safety Notes

- `createArticle`, `articleList`, and `articleDetail` carry public-safe SEO, category, tags, comment policy, content safety, canonical, and path metadata.
- `upsertTaxonomy` stores category/tag administration metadata in DynamoDB and returns only safe taxonomy summaries.
- `publish` writes public bundles with SEO, taxonomy, analytics context, comment policy, canonical mode, and safe article path fields.
- `queueComment` and `recordInteraction` remain protected, authenticated, and CSRF-checked actions in this BFF. Public unauthenticated comments, likes, CTA clicks, or form submissions should use a separate public ingestion surface with its own abuse controls; this BFF depends on auth-admin sessions by design.
- Interaction metadata rejects private fields and obvious email/phone values. Comment queue previews redact obvious email and phone values and do not return raw private contact data.

## Deploy

This repo follows the Zoolanding promotion graph:

- `dev` deploys development.
- `test` deploys testing, only from a merge from `dev`.
- `main` deploys production, only from a merge from `test`.

Required GitHub environment inputs:

- `CONTENT_HUB_CONFIG_JSON_BASE64` secret: non-secret compact JSON policy. It must not contain credentials or refs.
- `AUTH_SESSION_TABLE_NAME` variable.
- `AUTH_USER_STATE_TABLE_NAME` variable.
- `AWS_ROLE_ARN` variable.
- `AWS_REGION` variable, default `us-east-1`.

The Lambda defaults to 512 MB through the `FunctionMemorySize` SAM parameter. This gives more CPU to the cold read path that loads AWS SDK/DynamoDB clients while keeping the runtime configurable per environment.

## Local Tests

```powershell
python -m unittest discover -s tests -p "test_*.py"
sam validate
pip-audit -r requirements.txt
```
