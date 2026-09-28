# TEST runner IAM call matrix

Local reconciliation only: no grant or cloud execution is implied. All resources below mean the pinned account, `us-east-1`, exact TEST stack or exact immutable artifact key; they are not requests for new wildcard policies.

- **H**: existing `zoolanding-content-hub-test-deploy`, own Hub repository `environment:test` OIDC trust. Its source-IaC owner has not been located; do not import/recreate it implicitly.
- **I**: existing `zoolanding-deployer-image-upload-test-github-deploy`, own Image repository `environment:test` OIDC trust. Owner: Infra `lib/stacks/thn-test-deploy-identities.js`, invoked by `ServiceRepositoryBootstrapStack`.
- **IC**: existing `zoolanding-deployer-image-upload-test-cfn-exec`, CloudFormation service trust, same Infra owner. Image derives this exact identity and passes CreateChangeSet `RoleARN`; it accepts no free-form role selector. I's policy requires `cloudformation:RoleArn` equality and exact PassRole with `iam:PassedToService=cloudformation.amazonaws.com`.
- Hub's observed live **Stack.RoleARN is absent**. There is no separate HC to create: CloudFormation uses H's delegated permissions. Both Hub runners require that absence at preflight and every stack reread. A new role field, even consistently present in all observations, fails before packaging or any write; the runners never adopt or pass it.
- Human registry operator, registry mediator and Auth owner mediator are distinct authorities. None substitutes for H/I/IC.

## Direct SDK/package calls

| Phase / call | IAM action | Exact resource | Caller |
| --- | --- | --- | --- |
| Identity | `sts:GetCallerIdentity` | Action has no resource scope; actual account/role is checked | H / I |
| Preflight, waiter, readback | `cloudformation:DescribeStacks` | Own TEST stack; exact Auth/Image/Hub dependency stack when checked | H / I |
| Physical inventory | `cloudformation:ListStackResources` | Own TEST stack; Image also Hub authoring role inventory | H / I |
| Verified Original/Processed snapshots | `cloudformation:GetTemplate` | Own exact stack/change set | H / I |
| SAM package HeadObject/PutObject | `s3:GetObject`, `s3:PutObject` | Existing artifact bucket, own stack `/thn/run/attempt/source/` immutable keys | H / I |
| SAM bucket lookup if used | `s3:GetBucketLocation` | Same existing artifact bucket | H / I |
| Composed template upload | `s3:PutObject` | Same prefix, SHA-256 template key; AES256 and ExpectedBucketOwner | H / I |
| Prepare CREATE/UPDATE | `cloudformation:CreateChangeSet` | Own stack/change set; Image RoleARN must be IC | H / I |
| Service role delegation | `iam:PassRole` | IC only for Image; no Hub role in observed baseline | I |
| Review and execute | `cloudformation:DescribeChangeSet`, `cloudformation:ExecuteChangeSet` | Same exact stack/change set/hash | H / I |
| Discard unexecuted UPDATE | `cloudformation:DeleteChangeSet` | Only change set created by this run, never a stack | H / I |
| CREATE protection | `cloudformation:UpdateTerminationProtection` | Exact returned Image StackId, true only | I |
| Enable/disable ledger | `dynamodb:GetItem` | Exact registry table, singleton binding PK; tool fixes SK | H / I |
| Native retained-table checks | `dynamodb:DescribeTable`, `dynamodb:DescribeContinuousBackups` | Hub metadata/audit; Image transaction table; registry only in its bootstrap | H / I (own state); H (registry) |
| Native retained-bucket checks | `s3:GetBucketVersioning`, `s3:GetBucketPublicAccessBlock`, `s3:GetEncryptionConfiguration` | Own exact private bucket; ExpectedBucketOwner pinned | H / I |
| Runtime state | `lambda:GetFunctionConfiguration`, `lambda:GetAlias` | Seven exact Hub functions, or one Image private function; alias `test` | H / I |
| Private Image capacity | `lambda:GetFunctionConcurrency` | Exact Image private function, 0 closed / 2 enabled | I; H for dependency |
| Image dependency alias | `lambda:GetAlias` | Exact Image function alias `test` | H |
| Operator preflight | `iam:GetRole` | Exact registry/emergency operator, no mutation | H |
| Existing API route readback | `apigateway:GET` | Verified physical ContentHubApi `/apis/{id}/routes` | H |

The runner never calls Query, Scan, registry reserve/update, Lambda Invoke, DeleteStack, DeleteTable, DeleteBucket, version deletion or schedule enablement. CREATE failure leaves an inactive placeholder; it does not call DeleteChangeSet or disable protection. Ordinary-path GetTemplateSummary is not a substitute for these GetTemplate snapshots.

## CloudFormation effects, separate from caller readbacks

| Component | Required permission family to reconcile | Exact resource boundary | Executor |
| --- | --- | --- | --- |
| SAM transform/code fetch | Serverless transform permission; S3 GetObject | AWS Serverless transform and verified code keys | H / IC |
| Function/code/config/tags | Existing Lambda create/update/get/tag | Seven exact Hub functions, mediator separately, or one private Image function | H / IC |
| Versions and aliases | PublishVersion, CreateAlias, UpdateAlias, GetAlias, version reads | Same exact functions and `test`; old versions Retain only | H / IC |
| Private concurrency | PutFunctionConcurrency/GetFunctionConcurrency | One Image private function, 0/2 only | IC |
| Invocation policy | AddPermission/RemovePermission/GetPolicy | Exact qualified aliases and approved entry sources; registry separate | H / IC |
| Runtime roles | Existing role/policy/read/tag/basic-logs attachment and PassRole to Lambda | Seven short Hub roles; registry mutation role separately; one Image role | H / IC |
| Retained tables | Existing table create/update/describe/PITR/SSE/TTL/tag used by template | Exact service-private tables; registry separately | H / IC |
| Registry ResourcePolicy | PutResourcePolicy/GetResourcePolicy and DescribeTable | Exact registry table; no data write authority | H |
| Private buckets/policies | Existing S3 encryption/versioning/public-block/policy/tag configuration | Exact private buckets, never v1/public buckets | H / IC |
| API reconciliation | API Gateway GET/PUT required by HTTP API provider | Existing API, only exact three THN Body subtrees | H |
| Dormant schedules | Existing Events rule/target/read/tag creation | Three exact THN rules, DISABLED | H |

The inspected H identity lacks alias/version actions; its source ownership and exact registry ResourcePolicy provider permissions remain unresolved. The inspected I policy lacks GetTemplate, UpdateTerminationProtection and native retention/alias/concurrency readbacks. IC source lacked alias/version actions. Infra owns any minimal source correction to its I/IC roles; source tests or synth are not evidence that live grants changed. No new broad wildcard is authorized here.

Neither workflow supplies session policies, and neither inspected identity had a boundary or explicit deny. The approved registry ResourcePolicy grants H/I exact-partition GetItem; a separate DescribeTable deny excepts H and the mediator only. Its other strict metadata readbacks are not denied by that table policy, but must also be granted by the actual identity. Identity-only simulation cannot prove effective resource-policy access: test real workflow GetItem and exact native readbacks in D after reviewed bootstrap, including SCP/session/resource denies.
