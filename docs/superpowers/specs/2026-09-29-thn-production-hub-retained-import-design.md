# Production Content Hub retained-resource recovery

## Decision and observed state

Recover the failed production Content Hub state deployment by importing the four
retained resources into its existing CloudFormation stack. Preserve their data,
names, policies, and physical identities. Do not retry the current `state`
workflow until this recovery and a new protected state review are complete.

On 2026-09-29, `zoolanding-content-hub-prod` is `UPDATE_ROLLBACK_COMPLETE`
with termination protection and its 17 original resources. The failed update
left three named DynamoDB tables and one versioned S3 bucket outside the stack:

| Logical ID | Existing physical resource |
| --- | --- |
| `ServiceBindingRegistryV2Table` | `zoolanding-content-hub-prod-ServiceBindingRegistryV2` |
| `ThnContentHubV2AuditTable` | `zoolanding-content-hub-prod-ThnContentHubV2Audit` |
| `ThnContentHubV2MetadataTable` | `zoolanding-content-hub-prod-ThnContentHubV2Metadata` |
| `ThnContentHubV2PrivateStore` | `zlp-thn-ch-production-private-765932874577-us-east-1` |

Audit and Metadata report approximate `ItemCount=0`, have deletion protection
and PITR enabled. The bucket has versioning, encryption, and public access
block enabled; the read-only listing found no object versions. Registry has a
resource policy that denies general `DescribeTable`, `Query`, and `Scan`; its
contents are **unknown** and must be preserved. Its policy references
`zoolanding-thn-registry-production-mutation`, a role absent after rollback.
The six Lambda versions marked `DELETE_SKIPPED` in stack events no longer
exist. The production deployment-identities IAM patch is complete and the
27 EventBridge permission simulations passed.

## Recovery operation

1. Capture a fresh, redacted baseline of stack ID/status, original and
   processed template digests, parameters, tags, 17 resource identities, and
   the four external identities and configurations. Record the Registry
   resource-policy revision and digest directly. Never log secret parameter
   values, table items, or object content.
2. Build an import template from the **current** stack template, retaining
   the current 17 resource definitions and parameter values. Add only the
   four native resource declarations above with `DeletionPolicy: Retain` and
   `UpdateReplacePolicy: Retain`. Match live names and declared properties.
   For Registry, the interim declaration omits `ResourcePolicy`: its live
   policy remains in place, while the missing mutation role must not be
   referenced by an import template. Compare the live policy separately.
3. Validate the template and import identifiers locally. The production
   stack uses the SAM transform, so verify its expanded template as well.
   Use a dedicated, protected `IMPORT` review with exact stack, account,
   region, four logical IDs, four physical names, source SHA, and baseline
   digest. Reject the review unless its inventory contains **exactly four
   `Import` actions**, no adds/modifies/deletes/replacements, and no change
   to existing parameters or the 17 resources. Delete an unexecuted review
   change set after recording its digest.
4. Seek separate approval of that exact inventory and digest before import
   execution. Recreate a fresh change set from the same sealed template and
   recheck baseline, resource identities, policy revision/digest, permissions,
   and its canonical inventory against the approved review immediately
   beforehand.
   Stop if any comparison differs. After execution, require `IMPORT_COMPLETE`,
   21 stack resources, unchanged physical identities, and unchanged live
   Registry policy. Run drift detection on imported resources; compare the
   live Registry policy directly because the interim template omits it.

CloudFormation supports manual import for DynamoDB tables and S3 buckets,
but it does not verify that template properties match live properties during
the import. The strict preflight and post-import comparison are required.
If the SAM transform, IAM permissions, template references, or import
change set cannot satisfy this inventory, stop and revise the design. Never
delete or recreate Registry to make the import pass.

## Resume the protected Content Hub state release

The existing state guard expects these four resources as new `Add` actions.
After import, update its baseline and allowlist for their existing physical
identities. Review the resulting state change set against the freshly
imported 21-resource stack. It may add the remaining THN resources and may
modify the four imported declarations only where the full production
template requires an explicitly reviewed, non-replacing property transition.
The Registry resource-policy transition must be checked against the live
policy and the recreated mutation role; no broadening or loss of its deny
statements is acceptable. Do not allow unrelated changes to the original
17 resources, deletions, or replacements. Run local tests and permission
simulations before one protected review. Show its exact inventory and digest
for separate execution approval. Verify the stack, resource identities,
routes-closed state, and rollback evidence afterward. Production route
activation and user onboarding remain separate releases.

## Alternatives considered

- Delete Audit, Metadata, and the apparently empty bucket, then import
  Registry. This is irreversible and still needs an import and guard change.
- Delete and recreate all four. Registry contents cannot be proven empty and
  its policy deliberately blocks broad reads. This could lose production
  state and is rejected.

## Acceptance and stop conditions

The recovery is accepted only when the four existing resources belong to
the original stack with their identities and live Registry policy preserved,
the stack is healthy, and drift findings have been resolved or explicitly
explained. The subsequent state release is accepted only after a separate
protected review and approval, with routes still disabled. Any identity,
policy, parameter, inventory, or permission mismatch stops the operation
before execution; no exploratory release run is permitted.
