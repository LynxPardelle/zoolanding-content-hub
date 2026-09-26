# THN TEST authoring-only release operation

The TEST source branch contains the named-stage authoring route correction, but
source promotion does not deploy AWS. Added a guarded `authoring-patch` operation
to the private `Deploy THN Test` workflow. It uses the existing exact TEST SHA,
immutable build manifest and deployment identity checks. The new runner packages
only the verified authoring build, composes the current live Original template
with one changed `CodeUri`, and preserves every current stack parameter.

Before executing a change set, the runner requires the transformed template to
change only the authoring function code, one retained authoring Version and its
`test` alias. It rejects extra resources, replacements, API or permission edits,
and any Version removal without `Retain`. It rereads the live stack, templates,
inventory, routes and alias immediately before execution. Afterward it checks
the stack, protected resource identities, alias target and deployed code digest.
It records the previous package and retained version coordinates in the
encrypted private artifact bucket for a separately reviewed rollback.
No article or registry mutation is part of this operation.

The change is local pending review and has not been promoted or run in AWS.
Read-only inspection of the current TEST processed template confirmed the
expected authoring Function, Version and Alias shapes and an S3-backed
Original `CodeUri`. The actual future change set remains a separate gate: a
different transformed shape causes rejection before execution. Local checks:
465 runtime tests passed (5 skipped), and 133 release tests passed after the
strict processed-template assertion was added. Workflow YAML parsed locally.
`sam`, `actionlint`, and `pip-audit` were unavailable in this Windows shell;
the remote CI gates remain required before TEST promotion.
