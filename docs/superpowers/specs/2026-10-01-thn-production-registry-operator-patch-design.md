# THN production registry operator patch

Date: 2026-10-01

## Context and decision

The production Content Hub stack has completed its retained state release. Its private Registry mutation Lambda and table exist, while `EnableThnContentHubV2=false`, `ProvisionThnProductionRegistryOperator=false`, and the human principal is `BLOCKED`. The production registry operator role does not exist. The API runtime's first release requires a reserved production Registry row, but the current Hub `activate` release requires that row before review. Repeating Hub `state` is also invalid: its post-import inventory guard requires the one-time Registry policy transition that has already completed.

Add an `operator-patch` purpose to the existing protected Hub production release. It enables only the existing conditional Registry operator resources, before reserving a row or opening routes. Use the existing Hub CloudFormation stack so the role and invoke permissions remain stack-owned. A manual IAM role would be untracked by that stack and would bypass its reviewed change-set inventory. Activating the full Hub now cannot pass its Registry prerequisite.

## Scope and inputs

- Source authority remains the exact current `main` commit and production GitHub Environment. The manual workflow continues to require review, retained change-set digest, and a separate execute operation.
- The patch accepts only the existing IAM user ARN `arn:aws:iam::765932874577:user/Hector-admin` as `ThnProductionRegistryHumanPrincipalArn`. Its trust continues to require MFA present and age at most 300 seconds; no other principal, role wildcard, or long-lived credential is added.
- Require the existing Registry and Content Hub state flags to remain `true`. Set only `ProvisionThnProductionRegistryOperator=true` and the exact human principal. Preserve the current owner pool parameter, `EnableThnContentHubV2=false`, the production dependency gate, descriptor coordinates, auth policy version, and every other parameter by `UsePreviousValue`.
- The existing projected template defines the three resulting resources: `ThnProductionRegistryHumanOperatorRole`, `ServiceBindingRegistryOperatorInvokePolicy`, and `ServiceBindingRegistryOperatorInvokePermission`. The policy allows invoking only `zoolanding-content-hub-prod-ThnServiceBindingRegistryV2Mutation`. No browser route is created.

## Review and execution guards

Before review, verify AWS account and region, exact stack identity and termination protection, current parameters and 57-resource inventory, absence of pending change sets, absence of the proposed operator role, and the existing mutation Lambda identity. Verify the template projection and native provider handler permissions against the live CloudFormation resource schemas. Check the current GitHub `main` SHA and production Environment before and after credentials.

Create one retained change set with the existing private versioned package mechanism. Reject the review unless its complete inventory contains exactly three `Add` actions for the three named logical resources, with their expected resource types, no replacements or modifications, no extra dependencies, and the exact two selected parameter values. Fingerprint the baseline, templates, IAM roles/policies, S3 package versions, and native inventory in the review digest. Delete an unapproved preview using the existing bounded cleanup operation.

Execute only the same retained change-set ARN after approval of its exact inventory and digest. Recheck source, baseline, permissions, parameters, inventory, and expiry immediately before execution. Verify the stack is `UPDATE_COMPLETE`, termination protection remains enabled, all 57 previous logical/physical identities are unchanged, exactly three expected resources were added, and the role trust and Lambda invoke permissions match the reviewed template. If any check fails, stop without another automatic run and diagnose the observed state.

## Acceptance and limits

Local tests cover the closed parameter selection, exact three-resource native inventory, rejection of additional changes or replacement, baseline/source drift, expiry, and post-execution identity checks. Run the full repository suite, dependency audit, SAM validation, and workflow lint before the first push. A read-only AWS preflight must prove the concrete resource permissions before launching the review workflow.

This patch does not reserve or update the Registry row, choose `AuthPolicyVersion`, set API secrets, create a client account, enable article writing, activate routes, change TEST, or publish articles. Those later operations use their existing separate approvals and guards. The role is retained by CloudFormation; any later disablement or removal requires a separately reviewed change rather than an automatic rollback.
