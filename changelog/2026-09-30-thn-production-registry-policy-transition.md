# Production Registry policy transition after retained import

The protected Content Hub state review `36777618054` stopped in preflight before
uploading a package or creating a change set. The imported stack remained at
`IMPORT_COMPLETE` with 21 resources. Its Registry policy has 26 statements and
still refers to the mutation role deleted during rollback. The previous guard
pinned a raw policy JSON hash and suppressed the specific import guard reason.
It also preserved the imported Registry declaration unchanged, although the
approved recovery design requires a policy transition when that role returns.

The state candidate now keeps the existing Registry table and all other
imported resources, adding only `ResourcePolicy` to the Registry declaration.
It compares the live policy with the proposed one after normalizing AWS's
equivalent list and statement order forms. Exactly four allow statements may
rebind to the recreated mutation role; all deny statements and other policy
content must match. The change set guard permits only a nonreplacing Registry
policy modification alongside the reviewed THN additions. Execution checks
the same proof again and verifies the new role, policy, stack identities and
closed public API afterward. Guard failures expose only fixed diagnostic codes.

The inventory guard requires that Registry modification to appear exactly once;
an additions-only preview is rejected. The final authority check requires a
fresh post-import target snapshot before execution.
Post-execution verification accepts conditional SAM resources that remain
inactive while requiring every created resource to match the approved change
set and preserving the physical identities of all 21 imported resources.

Local tests, IAM simulation and replay against the current CloudFormation
template and live Registry policy are required before a new protected review.
That review and any later execution remain separate approvals; this source
change does not activate routes or publish articles.
