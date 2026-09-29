# Production registry policy principal

The protected Content Hub production state execution in run `36622160887` rolled back. CloudFormation reported `Invalid principal in policy document` while creating `ServiceBindingRegistryV2Table`. The production template projection had changed `zoolanding-content-hub-test-deploy` to `zoolanding-content-hub-prod-deploy`; the actual production deployment role is `zoolanding-content-hub-production-deploy`.

The projection now binds the exact existing role name before applying the general TEST to production name mapping. A regression test checks every deployment-principal statement in the registry table resource policy. The existing stack returned to its previous template and 17 physical resources.

The failed update retained two empty DynamoDB tables and an empty private S3 bucket outside the stack. After separate approval, all three were deleted following a fresh emptiness and stack-identity check. The 20 explicit names for the next state review are free again. This source change does not deploy resources.

A further read-only preflight found that the production table policy's `DescribeTable` deny excluded the Hub deployment role but not its separate CloudFormation execution role. The AWS DynamoDB table handler lists `DescribeTable` among its create permissions. The projection now exempts that exact execution role from the deny so the handler can stabilize the new table; no data actions are added to the exception.

IAM simulation confirms the execution role allows `CreateTable`, `DescribeTable`, `GetResourcePolicy`, and `PutResourcePolicy` on the exact new table ARN. Access Analyzer reports three `UNSUPPORTED_ACTION_FOR_CONDITION_KEY` findings for `ConditionCheckItem` with `EnclosingOperation`; the existing live TEST table policy has the same three findings, while AWS's DynamoDB transaction IAM guide documents that combination. This warning is recorded for a separate policy review and is not changed in this narrow deployment fix.
