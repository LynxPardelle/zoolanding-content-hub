# THN TEST runtime registry reader revision

Prepared a narrow source and guarded TEST operation for the dedicated auth
runtime's registry read. The deployed runtime returned 503 because the registry
table's explicit `GetItem` deny did not except its new execution role. The role's
identity policy already permits the exact binding read.

The source change adds one exact role to one deny exception. The dedicated
workflow can update only the existing registry table's resource policy after
the reviewed source is promoted to TEST. It checks the protected stack, the
complete original and processed templates, the effective policy digest, full
parameters, resource inventory, and API routes before and after execution.
No registry row, other draft, production resource, or public API behavior is
intended to change.

Local release tests and the runtime suite passed. The initial Windows runtime
suite needed local timezone data, which is normally present in the Linux CI
runner. Live original and processed table resources both matched the expected
pre-revision source except for CloudFormation's SAM metadata. This entry records
preparation, not a completed deployment or a working client login.
