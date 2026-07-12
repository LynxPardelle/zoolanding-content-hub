# Zoolanding Content Hub Agent Guide

<!-- zoolanding-hub-routing:start -->
## Zoolanding Knowledge Router

Read only the row needed for the current task, then inspect the local executable configuration or workflow that owns the behavior.

| Task | Read |
| --- | --- |
| Article package contract | [docs/api-driven-config/18-content-hub-article-packages.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/18-content-hub-article-packages.md) |
| Protected feature contract | [docs/api-driven-config/19-protected-feature-contract.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/19-protected-feature-contract.md) |
| Draft lifecycle and publication | [docs/11-draft-lifecycle.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/11-draft-lifecycle.md) |
| Fleet ownership | [docs/repository-map.md](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/repository-map.md) |

Critical repository-specific safety, deployment, and rollback rules remain local.
<!-- zoolanding-hub-routing:end -->

This repository owns the generic serverless BFF for protected Zoolanding content authoring.

## Read only what the task needs

- Start with [README.md](README.md) for the current contract, endpoints, release path, and local checks.
- For request handling, authorization, editorial lifecycle, or public projections, inspect [lambda_function.py](lambda_function.py) and the matching tests in [tests/test_content_hub_handler.py](tests/test_content_hub_handler.py).
- For IAM, environment inputs, schedules, or deployment shape, inspect [template.yaml](template.yaml), [samconfig.toml](samconfig.toml), and [.github/workflows/](.github/workflows/).
- For cross-repository ownership and shared contracts, use the canonical hub [repository map](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/repository-map.md) and [content-hub package contract](https://github.com/LynxPardelle/zoolandingpage/blob/main/docs/api-driven-config/18-content-hub-article-packages.md).
- Open [changelog/](changelog/) only when prior implementation, QA, or release history is relevant. `Codex.md` is a compatibility pointer, not a changelog.

## Non-negotiable boundaries

- Accept only allowlisted public identifiers, actions, content, locale, and safe form fields. Derive environment policy server-side and validate domain, auth profile, hub, tenant, and environment scope; the browser must never choose policy, tables, buckets, or storage prefixes.
- Protected reads/actions require the auth-admin HttpOnly session and an approved enabled user. Mutations also require cookie/header/stored-hash CSRF agreement. Enforce explicit action permissions; wildcard permissions are invalid and UI groups are hints only.
- `public-action` is limited to sanitized interaction writes. Fail closed unless origin, published/public article, published bundle, event policy, and rate limit all pass. Public comments/forms are not authorized by this surface.
- Preserve `draft|unpublished -> review -> approved -> published -> unpublished` transitions. Schedules pin immutable revisions; unpublish/archive keep bundle and revision history.
- Browser responses expose only allowlisted projections. Never return secrets, config values, table/bucket/object keys, signed URLs, actor identifiers, raw interaction/comment/form data, private contact data, or parser/internal error details.
- Keep release order `feature -> dev -> test -> main`. Pushes to `dev`, `test`, or `main` deploy, so do not merge or deploy without explicit authorization.

## Verification and records

- Verify claims against repository or tool evidence; never guess or hide failed/empty checks, and flag security risk.
- Run `python -m unittest discover -s tests -p "test_*.py"`, `pip-audit -r requirements.txt`, `sam validate`, and `actionlint` when available; report unavailable tools exactly.
- Put chronology in [changelog/](changelog/), reusable current guidance in `AGENTS.md` or `README.md`, and temporary plans/evidence in ignored `.superpowers/`.
- Never store credentials, tokens, raw environment values, signed URLs, private customer data, or other PII in documentation or logs.
