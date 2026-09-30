# THN production EventBridge rule permission proof

The first post-import Content Hub state review was preflighted locally before GitHub Actions. The approved IAM plan still used three untruncated EventBridge rule names; AWS simulation denied 27 action/resource pairs because CloudFormation creates rules from 25-character stack and logical prefixes. A local plan candidate now uses the exact generated prefixes already granted by the execution role. The 26-request simulation then allowed all 991 pairs, and representative concrete rule names allowed all 27 EventBridge pairs.

A second local replay exposed a guard bug: the live EventBridge resource schema includes `iam:PassRole` among a rule's handler permissions. The physical rule proof required that action in the same IAM request as the EventBridge ARN, although `iam:PassRole` applies to a role ARN and is covered separately by the full permission plan. The proof now simulates only `events:` actions against each concrete rule name, while rejecting other unreviewed service actions. The broader permission guard continues to require and simulate `iam:PassRole` on its IAM role resource.

The protected production review has not run. The production stack remains `IMPORT_COMPLETE` with 21 resources and no pending change sets; no route or article changed.
