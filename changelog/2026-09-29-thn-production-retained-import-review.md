# THN production retained Content Hub import guard

After the production `state` rollback, four named resources remained outside the protected Hub stack. This source change prepares an explicit four-resource `IMPORT` workflow with separate review and execute operations. The review deletes its unexecuted change set and transports only identities, hashes, and the private template coordinate. Execute recreates the change set from that exact versioned template and requires a matching approved digest.

The import template retains the 17 processed resource definitions already in the stack. Its four added declarations come from the sealed candidate that created the resources. The interim Registry declaration omits `ResourcePolicy` because it references a role absent after rollback; the live policy revision and hash are checked before and after import. The private bucket declaration records its observed AES256 default, disabled Bucket Key, blocked SSE-C, versioning, and public access block. Production routes remain closed.

The bounded IAM read policy is already applied in the production identities stack. Its workflow postcheck reported an incorrect resource count after AWS completed the update; the policy itself matches its source and all five bounded reads simulate as allowed. The identities postcheck correction is maintained in the infrastructure repository.

Local verification: CloudFormation `validate-template` accepted the 14-resource import template; SAM translation produced exactly 21 resources with all 17 prior definitions unchanged; the Hub test suite ran 537 tests with five skipped and no failures; `actionlint` and dependency audit passed. No Hub import change set or release was executed by this source change.
