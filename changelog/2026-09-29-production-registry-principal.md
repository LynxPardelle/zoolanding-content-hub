# Production registry policy principal

The protected Content Hub production state execution in run `36622160887` rolled back. CloudFormation reported `Invalid principal in policy document` while creating `ServiceBindingRegistryV2Table`. The production template projection had changed `zoolanding-content-hub-test-deploy` to `zoolanding-content-hub-prod-deploy`; the actual production deployment role is `zoolanding-content-hub-production-deploy`.

The projection now binds the exact existing role name before applying the general TEST to production name mapping. A regression test checks every deployment-principal statement in the registry table resource policy. The existing stack returned to its previous template and 17 physical resources.

The failed update retained two empty DynamoDB tables and an empty private S3 bucket outside the stack. After separate approval, all three were deleted following a fresh emptiness and stack-identity check. The 20 explicit names for the next state review are free again. This source change does not deploy resources.
