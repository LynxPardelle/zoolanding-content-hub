# THN TEST authoring patch pre-execution rejection

The first `authoring-patch` run for TEST source `2467eaa2fc32f5669eb8264bb936c98440bc4ea2`
stopped before `ExecuteChangeSet`. CloudFormation remained `UPDATE_COMPLETE`,
the authoring alias stayed on its previous version, and the direct read route
still returned `404`. The uploaded Original template changed only the authoring
function's `CodeUri`.

A non-executing diagnostic change set using that exact uploaded template and
the stack's previous parameters reached `CREATE_COMPLETE`. Its four resource
actions matched the allowlist: authoring function code modification without
replacement, one retained old Version removal, one new Version addition, and
the `test` alias retarget without replacement. The Original and Processed
templates, parameters, and change-set identity matched the runner's checks.
The diagnostic change set was deleted without execution.

The failure was the runner's pre-execution snapshot comparison. It compared
complete Lambda `get_alias` and `get_function_configuration` responses, which
include `ResponseMetadata`. Separate read calls have different request IDs
even when the alias and version are unchanged. Repeated live reads confirmed
that both responses compare equal after excluding only `ResponseMetadata`.
The local fix excludes that transport metadata during snapshot comparison;
the regression test still rejects a changed alias target or code digest.

Local verification after the fix: 134 release tests passed. The 465 runtime
tests passed (5 skipped) using the machine's installed IANA zoneinfo files;
the project's Windows virtual environment alone lacks those files. This
record does not authorize or imply another AWS deployment.
