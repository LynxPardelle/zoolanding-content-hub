# THN production import preview parameter order

The protected review run 36760956797 passed source validation, offline tests,
AWS role assumption, and the live stack, resource, template, and permission
preflight. CloudFormation created a four-resource IMPORT change set, but the
review stopped at `production_import_preview_baseline_changed` before generating
an approval digest or executing the import.

The native `DescribeChangeSet` response returned the six stack parameters with
the same names and values in a different order. The preview guard compared the
two lists in order. A captured response confirmed that the four changes were
Imports, the original candidate template matched, and the processed template
preserved all 17 existing resource definitions. The temporary change set was
deleted by ARN; the protected stack remains at 17 resources.

The preview now compares parameter entries without relying on provider order,
while still rejecting changed or duplicate entries. A regression test covers
reordering and duplicate rejection. The protected review and any import
execution remain separate, approval-gated operations.
