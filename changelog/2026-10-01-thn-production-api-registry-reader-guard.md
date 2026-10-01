# Production Registry reader patch guard

The first protected API Proxy review stopped before packaging or change-set creation. Its identity-policy simulation omitted the Content Hub Registry table's resource policy. That policy explicitly denies `GetItem` to the API deployment role. A simulation with the complete live resource policy reproduced the deny for the exact production binding key.

This change adds the protected `registry-reader-patch` release purpose. It builds a candidate from the deployed Original template, adding one exact API deployment role to three Registry read conditions. It rejects any other template or parameter change, requires a single nonreplacing native table `ResourcePolicy` modification, and repeats baseline, digest, policy, IAM simulation and identity checks at review and execution. The workflow skips a new SAM build and package for this purpose.

Local verification on 2026-10-01: 577 Python tests passed (5 skipped); `actionlint`, `sam validate --lint`, and `pip-audit -r requirements.txt` passed. AWS read-only checks found the protected 59-resource production stack in `UPDATE_COMPLETE`, Registry policy revision `1790818911396`, an exact match between live policy and CloudFormation Original template, and effective permissions for the table's native update handler. Candidate policy simulation returned `allowed` for the exact binding and `explicitDeny` for another or missing key. No AWS resources were changed by these checks.

The source-only promotion and protected production review remain separate. Execution requires approval of the review's exact native inventory and digest.
