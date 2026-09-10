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

## The Hair Narrative v2 Boundary (Build-only)

`template.yaml` also contains a separate, TEST-only Content Hub v2 scaffold for
The Hair Narrative. It is fail-closed: both `EnableThnContentHubV2` and
`ProvisionThnContentHubV2State` default to `false`, and activation additionally
requires the termination-protection gate, the exact emergency operator role,
the exact TEST CloudFront distribution, and immutable descriptor, digest, and
Auth Admin policy coordinates.

The isolated boundary reserves only these routes:

- `POST /features/content-hub-v2/read`
- `POST /features/content-hub-v2/action`
- `GET /features/content-hub-v2/public-media/{articleId}/{locale}/{revisionId}/{assetId}/{variantId}`

The candidate declares seven functions with seven separate short, deployable IAM role names: authoring,
private-asset collection, publication, public media, invalidation, emergency
withdrawal, and prepared-orphan collection. Authoring can read only the exact
THN auth rows and mutate private THN state; only the publisher can finalize the
public THN projection; public media is read-only; emergency withdrawal has no
API route and is invokable only by the named TEST operator. Worker schedules are
declared but explicitly disabled. They are persistent THN dependencies, not
temporary QA services, and were absent from the observed 17-resource live baseline.

The dedicated metadata and audit tables are retained, encrypted, deletion
protected, and PITR-enabled. The private bucket is retained, encrypted,
versioned, and blocks all public access. These state resources use their own
provisioning condition shared by the retained functions/roles; provisioning does
not open the THN HTTP or operator entry surfaces.

This infrastructure change does not activate or deploy the boundary. The v2
authoring entrypoint now rejects unknown operations before private access,
validates the exact THN scope and immutable server configuration, strongly reads
the namespaced session and current-user state, requires stored-hash-bound CSRF
proof for mutations, and exposes an atomic registry writer-epoch fence for final
writes. `writerMode=disabled` rejects every mutation. The local editor and
publication candidate described below implements the reviewed business flows;
that source state is not evidence of deployed or enabled runtime behavior.

The public-media module is now an implemented, physically isolated, read-only
origin. It accepts only the exact public TEST host and immutable media route,
strongly reads one `LIVE_MEDIA` manifest for the requested THN article, locale,
and revision, and fetches only the versioned S3 object named by that manifest.
Only `published`/`public`/`live` manifests and canonical JPEG, PNG, or WebP
variants can produce an immutable response; malformed, draft, working, orphan,
withdrawn, cross-scope, Zoosite, or direct-storage requests return a generic
no-store response. The public-media role cannot list, write, delete, read
unversioned objects, read authoring state, or inspect the registry.

The forwarded-host check is a transport precondition, not the data-authorization
control: the public front door owns header provenance, while the exclusive live
manifest and versioned object reference decide whether bytes are public. The
route exposes no private or authoring record even if a caller reaches the shared
API endpoint directly.

The emergency-withdrawal module is now implemented as an operator-only direct
invocation of the exact `test` alias. It has no HTTP, Function URL, schedule, or
event source. After the registry has already disabled writers and advanced the
writer epoch, it strongly reads the sealed THN projection manifest and removes
one page of at most 19 recorded article, locale-path, category, or public-media
pointers in a maximum-25-item conditional transaction. The same transaction
advances the manifest and page, checkpoints progress, and appends targeted
invalidation plus audit records, so retries resume safely without touching
private authoring data or another draft.

The internal modules stay physically isolated. Their locally implemented
publication and maintenance behavior remains subject to the registry fences,
explicit entry permissions and disabled schedules. Both v2 switches retain
their fail-closed defaults.

The consolidated architecture gate also pins the publisher's only private
object read to immutable revision packages at
`immutable-revisions/{articleId}/{locale}/{revisionId}/package.json`. It cannot
read working bodies, draft objects, sessions, another hub, or another tenant.
The locally connected publisher does not imply completed deployment or public QA.

Every SAM function, including the legacy Content Hub and registry mutation
function, uses an exact custom artifact allowlist. This prevents v2 handlers,
tests, documentation, workflows, and unrelated repository files from entering a
legacy or cross-function Lambda package.

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

- `dev` validates reviewed source changes.
- `test` validates source only, from the exact two-parent merge of the current `dev` tip with an identical source tree. It does not deploy AWS.
- `main` remains the production branch, only from a merge from `test`; this TEST change does not deploy or promote production.

The existing `deploy-test.yml` path is named **Validate Test promotion (no
deploy)**. Its two jobs have only `contents: read`, no GitHub Environment, no
OIDC, and no deployment variables or secrets. Both test suites, the SAM build,
exact package allowlists and independent artifact verification remain required.

Its artifact name contains `test-validation`; metadata uses
`zoolanding-test-validation/v1`, `purpose: validation-only` and boolean
`deployable: false`. It binds the full source SHA, service, run and attempt. The
transported inventory and hashes are checked after download by immutable ID.
It contains no release tools and cannot be used as a deployment or rollback
artifact. A green source promotion is not evidence of private access activation.

New THN AWS provisioning and activation must use the reviewed
[retained TEST lifecycle](docs/thn-test-release.md), starting with its exact
five-resource `registry-provision` operation against the unchanged shared
baseline. Do not use the former full-template automatic deployment as bootstrap:
default parameters would introduce only three of those registry resources and
invalidate the dedicated bootstrap baseline. Historical rollback remains a
separate privileged path for compatible prior release artifacts; it is not
disabled by this change and must not be used to bootstrap private activation.

Historical release/rollback inputs (not read by source validation):

- `CONTENT_HUB_CONFIG_JSON_BASE64` secret: server-only compact JSON policy. It must not contain credentials or secret references, and its value must never be copied or logged.
- `AUTH_SESSION_TABLE_NAME` variable.
- `AUTH_USER_STATE_TABLE_NAME` variable.
- `AWS_ROLE_ARN` variable.
- `AWS_REGION` variable, default `us-east-1`.

The retained legacy rollback parameter contract uses
`THN_V2_TEST_PARAMETERS_JSON`. Omission selects its historical defaults; it is
not a private bootstrap or activation path. When supplied, it must be a
closed object with exactly `schemaVersion: 1`, `environment: "test"`, and
`parameters` containing every key returned by `_thn_defaults()` in
`tools/prepare_test_parameters.py`. Partial selections and v1/shared parameter
overrides are rejected; no registry, account, writer mode, or epoch is changed.
Never place credentials or account contact information in this selection.

The unchanged historical rollback validates the selection before credentials and then
read the actual AWS account and TEST stack termination-protection state before
creating a change set. Enabling or provisioning v2 state requires an existing,
stable TEST stack with termination protection already enabled. The checker does
not enable protection itself. Runtime disable and retained-state provisioning
are independent parameters, not a verified recovery transition. Disabling an
already-enabled runtime removes conditional resources and is blocked by the
unchanged no-removal change-set guard. Such a transition needs a separately
reviewed recovery path; this tool does not establish it or weaken that guard.

This is delivery plumbing, not evidence that the private editor, publisher,
owner onboarding, or TEST activation is complete. A prior rollback artifact
must include this parameter contract; an older artifact cannot be silently
treated as compatible.
For a supplied THN selection, historical rollback requires the packaged tool to report
`thn-test-selection/v1` before credentials. A legacy tool without that capability
fails the release instead of silently ignoring the selection. With no THN
selection, the compatibility check is skipped and the prior path is unchanged.

`DescribeChangeSet` does not return a `ChangeSetType` field. The TEST runner binds
`CREATE` or `UPDATE` when creating the change set and reviews the exact returned
ARN, name and stack; an absent response field is accepted, while a conflicting
field is rejected. Parameter, removal and replacement guards remain unchanged.
See the [AWS response contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeChangeSet.html).

The Lambda defaults to 512 MB through the `FunctionMemorySize` SAM parameter. This gives more CPU to the cold read path that loads AWS SDK/DynamoDB clients while keeping the runtime configurable per environment.

## Isolated fixed-article authoring candidate (not deployed)

The v2 authoring entrypoint has local implementations for article creation,
optimistic bilingual saves, list/search/filter, detail, fixed taxonomy, asset
metadata reads, validation, and sanitized working-revision preview. The existing
v1 entrypoint and its artifact allowlist are unchanged.

`input.contentHub.data` carries the operation input. Creation requires `locale`
and a 32-character lowercase hexadecimal `idempotencyKey` retained across retries.
`updatePackage` requires `articleId`, `locale`, the last `concurrencyToken`, and
`package`. The fixed package contains title, summary, seriesId, private tags,
cover metadata and Quill Delta; it does not accept HTML or a custom URL. An old
token produces `409 edit_conflict`, except for an exact replay of the last
acknowledgeable save. Do not generate a new idempotency key on a network retry.

Private packages are immutable version/digest-checked S3 objects. Bounded private
metadata writes condition-check the registry, current actor, active session and
concurrency token in one transaction. Reads revalidate the actor before returning
private data. QA records have server-owned 30-day retention metadata and cannot
be read by the client-owner. Retention metadata does not imply cleanup is wired.

`uploadAsset` now uses the isolated private Image Upload v2 processor through
IAM and its TEST alias. It creates a 15-minute, three-attempt transaction bound
to the current article revision, locale, actor purpose, writer epoch and image
digest. Final asset registration rechecks the article concurrency token,
registry, current user and session in the same DynamoDB transaction. Repeating
the same upload while that revision is current reuses its processed transaction.

The browser sends at most 4,194,304 normalized bytes (5,592,408 base64 characters),
with at most 65,536 UTF-8 metadata bytes and a 5,750,000-byte envelope. Accepted
types are JPEG, PNG and WebP; alt text is required. Full decoding, dimension
checks and metadata stripping belong to the private image processor, not the
public v1 uploader. The private asset record pins all four S3 variant versions.

`assetList` accepts an optional `assetId` to return **one** authorized image as
base64 with `no-store`. Without it, only safe asset metadata is returned.
`publicBundlePreview` emits inert `data-private-asset` references for inline
images. The client obtains Blob URLs from protected reads before rendering;
there is no new GET image route, signed URL or public object access.

The private client desk, origin/SSR integration, edit/upload audits and private
media lifecycle are connected and tested in the isolated local candidates.
This is **not** activation: `publish` and `unpublishArticle` remain unavailable;
no publisher is invoked. Public delivery and environment acceptance are still
unfinished, and all candidates remain undeployed.

The read-only `tests/test_content_hub_v2_runtime_contract.py` compatibility check
requires `THN_RUNTIME_READ_SOURCE` to select a verified local Runtime Read
checkout. Its explicitly approved local opt-in uses
`localePolicy: "published-only"` to exclude unpublished translations; a separate
regression preserves legacy fallback when the option is omitted. A skipped
compatibility test is not a passing public-delivery gate. No reader release or
actual draft opt-in is implied by this local test.

## Dedicated retained TEST lifecycle

The [THN lifecycle guide](docs/thn-test-release.md) defines the separate
`registry-provision`, `provision`, `enable` and retained-runtime `disable`
operations. It preserves the shared live template and ordinary no-removal guard;
the older optional selection path above is not this lifecycle workflow. The
[IAM matrix](docs/thn-test-iam.md) records exact caller/execution-role prerequisites.
All new work is local A–C reconciliation, not deployment D.

## Local Tests

### Private desk lifecycle (local candidate)

Private article commits maintain working-image references together with an
article concurrency check, current actor/session checks and the registry epoch.
They cannot change published-image references. Completed edits/uploads append
redacted durable audit events. Private collection accepts at most 20 exact image
candidates, claims each conditionally, and deletes only pinned private-upload
versions unused for at least seven days. Missing tracking fields fail closed;
existing records require a reviewed migration before collection.

The private collector schedule stays disabled. Do not enable its empty scheduled
event: activation needs an approved exact candidate source and environment
acceptance. Public publication is still unavailable. Pure projection helpers and
consumer compatibility tests do not activate the publisher or create public data.

`content_hub_v2_preparation.py` orchestrates exact-key, versioned private
preparation. `content_hub_v2_projection_store.py#AwsPreparationStore` implements
its SDK adapter with injected clients and server-resolved bucket bindings. It
records fenced cleanup intents before writes, verifies image digests, persists
exact receipts and safely reuses immutable versions after a lost receipt commit.
It returns a manifest candidate without installing any live pointer. The adapter
is locally tested but is not wired into a Lambda or enabled by the current role.

`content_hub_v2_projection_delta.py` computes the bounded public-row transition
for one bilingual article, including selected-locale promotion, obsolete-media
removal and exact withdrawal/cache inventories. Storage-only family/hub/revision
markers match emergency withdrawal and are omitted from Runtime Read responses.
Both publication and emergency-withdrawal cache inventories include Home.
The delta is data, not a transaction: never apply its changes individually.
`content_hub_v2_finalization.py#AwsPublicationStore` now combines that transition
with current actor/session/epoch conditions, the private article CAS, published
image references, permanent path reservation, preparation state, projection
manifest checkpoint and durable audit/outbox in one conditional transaction.
The adapter loads pinned private packages itself; it accepts no browser-supplied
HTML or public records. Publication receipts allow safe retries without duplicate
audits or outbox entries. Unpublishing preserves the private working revision and
reserved URL while removing only that locale's public delivery.

Call `allocate_publication` before immutable preparation to select the URL from
the title and reserve a collision-safe variant. This private-only allocation
preserves the selected path and timestamps across retries and cannot publish.
`content_hub_v2_manifest_update.py` maintains one closed withdrawal page per
article, using exact private neighbor links rather than a scan. Missing or stale
live checkpoints require reconciliation; the adapter does not repair or reopen
an emergency-withdrawn manifest automatically.

These adapters are now wired locally through the independently authorized
publisher and the authoring gateway. Separate invalidation and prepared-orphan
workers consume bounded durable records; schedules and activation defaults stay
disabled. Local exact-IAM, SDK, artifact, consumer and browser checks cover the
complete candidate. This is not a deployed or signed release: operational
bindings, release gates, owner enrollment and live TEST acceptance remain
mandatory before enabling publication for a client.

The approved local publisher-session exception grants only an in-transaction
condition on the dedicated THN session table, with no session reads, writes,
lists or returned attributes. `content_hub_v2_actor_fence.py` supplies the shared
subject/purpose/scope/version/expiry/revocation checks. The permission has not
been applied to AWS; the deployed publisher remains dormant. The local publisher
independently rereads the dedicated CurrentUserStateV2 record and checks the
SessionV2 record only inside the atomic transaction. Publication audit writes
are transaction-only; reads have a separate exact-partition permission.

```powershell
python -m pip install -r requirements.txt -r requirements-release.txt
python -m pip check
python -m unittest discover -s tests -p "test_*.py"
python -m unittest discover -s tests_release -p "test_*.py"
sam build --no-cached
python tools/check_lambda_artifacts.py
sam validate
cfn-lint -t template.yaml -r us-east-1
pip-audit -r requirements.txt -r requirements-release.txt
actionlint
```

Run the separate `cfn-lint` command with version **1.56.0**, matching the TEST
deploy and candidate-validation workflows. SAM CLI 1.164.0 instead bundles
cfn-lint 1.52.1 and SAM Translator 1.111.0. The former SAM-events template
produced three W1028 warnings because the same enable condition appeared on
each path, method and integration URI. The reviewed lifecycle reconciliation
now uses the exact conditional Body subtrees and permissions, preserving that
route contract without redundant nested conditions. No lint rule is suppressed;
the supported separate validation command remains the pinned command above.

On Windows, Python's `zoneinfo` tests require an IANA timezone database. Set
`PYTHONTZPATH` to a trusted local zoneinfo directory (for example Git for
Windows' `mingw64/share/zoneinfo`) when the `tzdata` package is not installed.
