# Zoolanding Content Hub Notes

This repository owns the generic serverless content-hub BFF for draft-configurable article/content authoring workflows.

Durable decisions:

- The browser contract is same-origin `POST /features/content-hub/read` and `POST /features/content-hub/action`.
- Browser requests may carry only public draft, hub, source/action, article, taxonomy, asset, revision, schedule, locale, and safe form fields.
- Server-only policy, table names, bucket names, auth profile details, authorization decisions, signed URLs, tokens, credential refs, and raw secrets must never be returned to the browser.
- The BFF reuses auth-admin HttpOnly sessions by reading the shared auth-admin session/user-state DynamoDB tables. Mutations require the readable CSRF cookie to match the `X-ZLP-CSRF` header and the stored session CSRF hash.
- Authorization is action-scoped. Draft route `allowedGroups` are only UX hints; this Lambda must enforce roles server-side for every read/action.
- Article packages and published bundles are stored as S3 JSON files under deterministic `content-hubs/{environment}/{hubId}/...` prefixes. DynamoDB stores compact indexes, status, taxonomy, revision, schedule, asset, and moderation metadata.
- Initial public media URLs must be unsigned public URLs or draft-approved CDN URLs. Signed URLs are rejected from browser-facing payloads.
- Publish in this BFF creates validated published bundles and metadata. Propagating those bundles into Angular public `runtime.contentHubs.publicArticles` remains a separate runtime-read/front-door integration unless explicitly wired.

