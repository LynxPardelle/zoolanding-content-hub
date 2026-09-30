# THN production import processed template ordering

The protected review run 36763127266 passed validation, offline tests, role
assumption, and the live AWS preflight. It created a change set with exactly four
Imports, then stopped at `production_import_processed_template_changed` before
creating an approval digest or importing resources. The temporary change set
was deleted by ARN; the protected stack remains at 17 resources.

CloudFormation returned both processed templates as nested `OrderedDict`
objects. Nine existing resource definitions had identical canonical content but
a different property order in the import preview. Direct `OrderedDict` equality
treated them as different. We checked the native response with the same pinned
Python AWS client used by the workflow; all 17 existing resource definitions
have equal canonical content, and the preview contains only the four intended
additional resources.

The guard now compares the original template and each existing processed
resource by canonical content, independent of mapping order. Its regression
test reproduces the native ordering and still rejects changed values in either
template. Review and import execution remain separate, approval-gated
operations.
