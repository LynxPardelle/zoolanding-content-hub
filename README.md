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
- `taxonomyList`
- `moderationQueue`
- `assetList`
- `revisionList`
- `publicBundlePreview`

## Supported Actions

- `createArticle`
- `updatePackage`
- `uploadAsset`
- `validate`
- `submitReview`
- `publish`
- `schedule`
- `moderateComment`
- `restoreRevision`

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

## Local Tests

```powershell
python -m unittest discover -s tests -p "test_*.py"
sam validate
pip-audit -r requirements.txt
```

