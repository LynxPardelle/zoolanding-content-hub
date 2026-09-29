# Production EventBridge resource proof

The 2026-09-29 Hub state execution rolled back because the CloudFormation role lacked `events:DescribeRule` on the rule name that CloudFormation generated. The permission plan and IAM policies both used an impossible long ARN pattern, so their wildcard simulation passed while the actual rule was denied.

The production preflight now derives the concrete generated name for new rules and uses the physical name from change sets for existing rules. It requires the matching narrow plan pattern and simulates the provider actions against a concrete ARN. A stale pattern or an IAM deny stops review before an execute can be authorized. Unit tests cover the stale plan, a live deny, new rules, and updates to existing rules.

This source change requires a new production permission plan, review, and digest before a later Hub execution. No production routes or schedules were enabled by this patch.
