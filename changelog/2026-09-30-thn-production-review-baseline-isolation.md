# THN production review baseline isolation

Protected Content Hub execution `36795147420` stopped before calling
`ExecuteChangeSet` with `production_baseline_changed`. CloudFormation remained
`IMPORT_COMPLETE` with 21 resources, deletion protection enabled, and the
reviewed change set still available. No service or blog route was activated.

The earlier fix isolated the new state candidate, but review preparation still
called `parse_template` on the mutable Original template returned by boto3.
When it replaced the historical Lambda `CodeUri` with a sealed recovery
coordinate, it also changed the baseline object used to compute the review
digest. The actual production template retained its original `CodeUri`, so
execution correctly rejected the mismatched baseline. Reading the sealed
recovery object and live Original template confirmed the difference.

The release workflow ran its older offline guard files but did not include a
review-to-execute regression for this mutable-template path. The new test
creates the review record and passes it through the execute verifier and the
final authority check without making an AWS change. The protected workflow
now runs that test before assuming production credentials.

Recovery preparation now copies the Original template before changing its
Lambda code coordinate. Before saving a review record, the workflow captures
the live baseline again and requires its fingerprint to equal the proposed
record fingerprint. A regression test drives the review path with a mutable
`OrderedDict`: it failed with the old code, then passed after isolation. The
fresh-baseline check also failed its red test before being added. This patch
does not relax inventory, permission, source, or execution guards.

The prior review record and digest cannot be reused. A new protected review
after source promotion must produce and verify a new inventory and digest;
execution needs separate approval.
