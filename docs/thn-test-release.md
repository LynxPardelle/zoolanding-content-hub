# Retained THN TEST lifecycle

Source preparation is not evidence of a deployment or a completed D gate. Production, v1 behavior, other drafts, and the historical rollback no-removal guard are unchanged. The dedicated [workflow](../.github/workflows/deploy-thn-test.yml) owns the operations below; do not bypass it with `sam deploy`.

## Source validation is separate from AWS execution

The existing [TEST promotion workflow](../.github/workflows/deploy-test.yml)
now validates only. It preserves the exact dev merge/tree gate, runs both suites
and package checks, and verifies the transported artifact by immutable ID and
full inventory digest. Neither job selects an Environment, requests OIDC, reads
deployment vars/secrets or executes AWS. It cannot create a partial registry.

The validation artifact has schema `zoolanding-test-validation/v1`, purpose
`validation-only`, and boolean `deployable: false`. Its distinct name includes
`test-validation`; it contains no release tools. It is not a deployment or
rollback artifact. Historical rollback still requires its original
`zoolanding-test-release/v1` metadata and rejects validation metadata before
credentials. Its existing compatibility and no-removal checks remain mandatory.

Only the private workflow produces `zoolanding-thn-test-release/v1` artifacts
for the operations below. Its source, identity, immutable transport, dependency,
retention and exact live-baseline checks are unchanged. Source promotion does
not authorize skipping those checks or establish that the client can sign in.

## Verified baseline and operation boundaries

The file entrypoint delegates to the package entrypoint so registry helpers and
the CLI use the same safe exception class. Known release-boundary and change-set
review failures print their static rejection code and exit nonzero. Unknown or
provider exceptions keep the generic message; no raw SDK response is logged.
This diagnostic distinction does not relax any review or deployment guard.

Processed-template drift includes at most 16 structural locations and closed
node-type labels. Only fixed CloudFormation schema names are emitted; other
dictionary keys use anonymous indexes in sorted key order. Values are never
logged. Depth and output bounds apply, and the same rejection and unexecuted
change-set cleanup remain mandatory. A diagnostic is not permission to normalize
or ignore an unexplained difference.

The SDK decodes JSON `GetTemplate` bodies as nested `OrderedDict` objects,
whose equality depends on insertion order. The THN release loader recursively
copies those mappings into ordinary dictionaries before comparing templates.
JSON object key order is not configuration; array order, keys, values and scalar
types remain untouched. No field is filtered, no difference is suppressed and
all existing change-set and post-execution checks still run. Text/YAML decoding
is unchanged. This fixes an order-only rejection that produced an empty
structural-difference report; it is not a general drift-normalization rule.
See [Python mapping equality](https://docs.python.org/3/library/collections.html#collections.OrderedDict)
and [JSON object/array semantics](https://www.rfc-editor.org/rfc/rfc8259#section-1).

The registry bootstrap compares the initial and final `DescribeChangeSet`
payloads without their top-level `ResponseMetadata`. Request IDs, HTTP headers
and retry counts describe individual SDK requests, not change-set configuration.
Both responses remain unmodified. Every other returned field is compared,
including unknown fields, nested fields named `ResponseMetadata`, identities,
status, parameters and resource changes. Real payload drift still stops execution
and deletes only the runner's own unexecuted change set. All independent template,
inventory, parameter, status, retention and post-execution checks remain required.
This exception applies only to SDK transport metadata at this comparison boundary.

The 2026-09-08 read-only TEST observation found a protected, stable Hub stack with **17 existing shared resources**, no THN seven-pair runtime, and none of the five mediated-registry resources. The exact registry-operator parameter and human role were also missing. These are observations, not assumptions inferred from the candidate template. Recheck them at execution. Image TEST was absent; its separate private-only CREATE path does not create v1 resources.

| Operation | Allowed effect | Required before it runs |
| --- | --- | --- |
| `registry-provision` | Preserve all 17 live resources; add exactly the registry table, mutation role/function, operator invoke policy/permission | Existing exact human operator; verified live Original and Processed templates and 17-resource physical inventory; H deployment permissions |
| `provision` | Add the seven retained function/role pairs, aliases/retained versions, private state and three disabled schedules; keep the three THN API paths closed | Completed registry bootstrap; existing v1 shared base; stable protected Hub TEST stack |
| `enable` | Open only the three reviewed THN path subtrees and exact invoke permissions | Closed writer ledger, active binding, matching immutable descriptor/digest/policy, protected/enabled Auth and Image TEST, exact emergency operator, origin gate |
| `disable` | Close those THN entry surfaces only; preserve functions, roles, aliases, state and dormant schedules | Writers already disabled and epoch advanced; retained-runtime template already installed; public withdrawal completed separately |

Registry provisioning is a separate operation in the existing stack, not a second stack. It packages only the existing mediator code. It adds only `ServiceBindingRegistryOperatorRoleArn` and the two exact registry conditions; every existing parameter uses `UsePreviousValue`. Both template snapshots must be verified. Any missing, duplicate, substituted or extra Add, shared Modify, Remove, replacement, changed StackId, API/global field change, or changed live inventory is rejected. Two post-execution observations require the original 17 physical resources plus exactly the reviewed five additions and their types. Repeating bootstrap against an already bootstrapped stack is rejected, not treated as a new bootstrap.

## Provisioning order without a consumer cycle

1. Resolve the existing human role and deployment IAM prerequisites through their reviewed owning IaC. The release runner does not create that human role.
2. Run `registry-provision`: it requires no Auth table, Image alias, THN authoring role, descriptor activation or registry row. It creates no HTTP route and leaves all seven THN pairs absent.
3. Provision Auth retained state and Hub's closed runtime; create Image's closed private stack. These phases must not require consumers to be enabled. Hub's shared Auth table names are existing legal parameters retained from the stack; dedicated THN table/function identities are fixed template names. They are not proof that those external resources already exist. No synthetic ARN or empty selector substitutes for an enable prerequisite.
4. Reserve/update the registry through the approved human mediator, then enable Auth, Image and Hub in dependency order while writers remain disabled. Authoring, descriptor/origin and exact resource-binding checks remain mandatory. Front-door activation and writer-mode changes are separate reviewed actions.

The seven pairs are Authoring, PrivateAssetCollector, Publisher, PublicMedia, InvalidationWorker, EmergencyWithdraw and PreparedOrphanCollector. They are approved persistent THN dependencies declared by this candidate, **not physically present in the observed 17-resource baseline** and not extra QA services. The enabled private Image function is a separate one-pair dependency.

## API and rollback boundary

The HTTP API remains the existing `ContentHubApi`. The composer copies its verified live processed Body and replaces only these exact subtrees:

- `POST /features/content-hub-v2/read`
- `POST /features/content-hub-v2/action`
- `GET /features/content-hub-v2/public-media/{articleId}/{locale}/{revisionId}/{assetId}/{variantId}`

Methods, payload format 2.0, authorizer behavior, integration timeout and alias-qualified source permissions are pinned against the former SAM-generated route contract. Every v1 path and all other Body fields remain semantically identical; shared source resources are copied without mutation. Missing snapshots, extra methods/paths, changed API physical identity, host, authorizers, CORS, stage or v1 integration fields fail closed. There is no new API or broad logical-ID exception.

`disable` does not deploy an old artifact that deletes the runtime. State has `DeletionPolicy` and `UpdateReplacePolicy: Retain`; superseded Lambda Version removal is allowed only when the change set explicitly reports `PolicyAction: Retain`. Functions, roles, aliases and schedules cannot be removed or replaced. The generic no-removal reviewer remains strict outside this dedicated verified boundary. No automatic rollback, stack deletion, bucket/table/version deletion or protection disablement is attempted.

## Registry readers and inspection

The registry policy uses IAM action names rather than DynamoDB API-operation
names. `BatchExecuteStatement` and `ExecuteStatement` are covered by the existing
unconditional `PartiQLSelect/Insert/Update/Delete` denials. `TransactGetItems`
is denied as `dynamodb:GetItem` with `StringEquals` on
`dynamodb:EnclosingOperation: TransactGetItems`, for every principal. That
condition does not match an ordinary GetItem with no enclosing operation;
all existing consumer/partition restrictions still apply. Do not remove the
transaction deny or use an `IfExists` condition that also blocks ordinary reads.
No approved allow, principal list, partition or mutation-role grant changed.
See the [API-to-IAM mapping](https://docs.aws.amazon.com/service-authorization/latest/reference/list_dynamodb.html)
and [transaction IAM conditions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/transaction-apis-iam.html).

Auth's exact intended runtime role is an approved GetItem consumer. Deployment callers H and I have a table ResourcePolicy GetItem allow on one exact binding partition, with `Null=false` and explicit missing/outside-partition denies. The tools strongly read only PK `SERVICE_BINDING#test#thn-journal-test-v2`, SK `REGISTRY#V2`; they never reserve or update it. IAM restricts the partition, **not the sort key**: another SK in that partition is not excluded by this IAM grant. Reservation/audit partitions, Query, Scan, other listing and writes remain denied. A separate DescribeTable deny permits only the mediator and H; no such exception is added for I or the human.

The human's `tools/service_binding_registry_operator.py inspect` invokes the same private mediator with a fresh nonce. Its fixed handler performs strong binding/reservation/binding reads, validates exact canonical records and returns only a closed sanitized proof. It performs no write, audit append, repair or implicit reservation. The human still has the pre-existing reserve/update-capable invocation authority; `inspect` is not an IAM inspect-only role. There is no dual OIDC trust or deployment use of that human authority.

H and I were read-only verified with exact own-repository `environment:test` OIDC trust, no attached managed policy, no boundary or explicit identity deny, and no workflow session policy. Their identity-policy simulations did not grant GetItem. The new resource-policy source is not proof of effective cloud access: after bootstrap, D must test the actual GetItem under each real workflow session, including SCP/session/resource denies. See the [IAM call matrix](thn-test-iam.md) for other concrete prerequisites.

## Post-QA closure and retention

Before route or permission disablement, disable writers and advance the ledger epoch, withdraw QA public pointers through the approved publication/emergency path, invalidate and verify public closure. No successful in-flight response may finalize publication using the old epoch. Image concurrency zero prevents new starts; it is not IAM revocation or cancellation of in-flight invocations. Auth owns QA identity/group/session closure separately. QA private records remain owner-invisible by purpose and server authorization.

The server records `retentionUntil = createdAt + 30 days` for QA, but **30 days is metadata, not automatic deletion**. Neither Hub private metadata/audit table has QA TTL nor does either private object bucket have a lifecycle purge. Image's transaction TTL is for upload transactions, not private QA articles/assets. Retained versions and tables remain until a separately reviewed targeted action; no zero-cost or automatic-cleanup claim is made.

| Persistent THN maintenance dependency | Declared state and purpose | Retention / owner |
| --- | --- | --- |
| PrivateAssetCollector + daily rule | `DISABLED`; bounded pinned unused-private-asset cleanup after its own eligibility period, not QA 30-day cleanup | Hub; function/role/alias retained across disable |
| InvalidationWorker + minute rule | `DISABLED`; bounded publication invalidation outbox | Hub; persistent publication dependency, not QA service |
| PreparedOrphanCollector + daily rule | `DISABLED`; explicitly identified unreferenced prepared projections | Hub; persistent recovery dependency, not QA service |
| EmergencyWithdraw | No schedule or HTTP; exact operator invocation only while authorized | Hub; persistent rollback dependency |

No schedules are enabled by this workflow. The closeout verifier records checks; it does not itself clean cloud resources. Any future QA cleanup needs exact reviewed rows/versioned objects and expired-retention evidence, without adding a service by default.

## Mandatory local and CI checks

Install both dependency files, then run both suites (also required in the dedicated release and credential-free PR/candidate jobs):

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

Use cfn-lint 1.56.0. New parser/lifecycle tests live in `tests_release`; none has an optional skip. For the pre-existing cross-repository Runtime Read compatibility tests, set `THN_RUNTIME_READ_SOURCE` to the independently verified reader worktree; an omitted external check is not evidence of that delivery gate. Windows also needs a trusted IANA timezone database as described in the README.

The immutable artifact contains the complete file inventory, metadata and release tools (including `thn_registry_provision.py`). Digest, file-set and symlink checks run before credentials; the deploy job does not check out source. The feature-branch registration job has no environment, checkout, AWS credentials or deployment. Actual manual execution requires `refs/heads/test`, exact repository and reviewed full SHA. Registration is not a production promotion or a deployment.

Primary contracts: [CloudFormation change sets](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html), [DescribeChangeSet response](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeChangeSet.html), [HTTP API Body](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-api.html), [DynamoDB fine-grained access](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/specifying-conditions.html).
