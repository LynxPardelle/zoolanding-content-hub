# Preserve article publication dates on republish

Updating an article cover creates a new editorial revision. Republishing that
revision now retains the article's existing `publishedAt` in its metadata,
published bundle and publish response, so routine edits do not change the blog's
publication ordering. `updatedAt` still records the current publication action.
An article without an existing publication date receives the current timestamp
on its first successful publication.

The change is limited to the legacy Content Hub publish handler. It does not
modify THN/V2 code, infrastructure, permissions, editorial transitions or the
article body. Regression coverage includes first publication, a new cover
revision with unchanged body, and unpublish/republish.

The normal production workflow gains a single compatible v1 release mode. Its
AST guard accepts only these publication-date semantics, preserving the existing
promotion graph and exact source selection. The candidate replaces one module
inside the deployed v1 ZIP and retains every dependency. A native CloudFormation
preview built from the deployed template must change only the existing Lambda
Code; V2, IAM, routes, parameters, environment and resource changes are rejected.
Private versioned recovery artifacts and review fingerprints reuse the retained
release primitives. Drift is checked before execution and readback; no broad SAM
deployment, direct Lambda update or local execution path is introduced.
