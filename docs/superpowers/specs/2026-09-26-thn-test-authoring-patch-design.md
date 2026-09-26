# THN TEST authoring code patch design

## Decision

Add an `authoring-patch` operation to the existing private Content Hub TEST
workflow. It updates the already provisioned authoring Lambda through one
guarded CloudFormation change set. It must not change the shared Content Hub,
the HTTP API, permissions, registry, state stores, other THN Lambdas, schedules,
or production.

## Current state and goal

The QA account completed sign-in and MFA, but the TEST journal desk's article
list receives `404 not_found` from the authoring handler. The reviewed fix
accepts the named `/test` stage prefix for exactly the read and action paths.
It reached `dev` in PR #100 and the `test` source branch in PR #101. The TEST
promotion workflow and CI passed; they do not deploy AWS.

Read-only TEST inspection found an active
`ThnContentHubV2AuthoringFunction`, a published
`ThnContentHubV2AuthoringFunctionVersion*`, and
`ThnContentHubV2AuthoringFunctionAliastest` pointing to version 2 with no
weighted routing. The read and action invoke permissions are distinct
resources. This is an observation for design, not a claim that a future run
will see the same inventory. Every execution must read it again.

## Release entry and artifact

The operation runs only through `.github/workflows/deploy-thn-test.yml` on
`refs/heads/test`, with an exact reviewed source SHA, the existing TEST
environment and OIDC deployment role, and the current concurrency group. The
validation job runs the full suites, SAM build, artifact allowlist and pinned
template checks without AWS credentials. It produces the existing immutable
artifact and manifest; the deployment job verifies their identity and complete
file inventory before obtaining credentials.

The packaging step takes the authoring artifact from that verified build.
The composer starts from the live CloudFormation Original template and
replaces only `Resources.ThnContentHubV2AuthoringFunction.Properties.CodeUri`
with its reviewed, source-bound package URI. Every other template node,
including the function's handler, role, environment, alias setting, both
invoke permissions and shared API, must compare equal to the live template.
Every stack parameter uses its current value; no caller supplies a partial
parameter set or a resource name. The package URI and artifact bucket must
match the workflow's exact run, source SHA and manifest.

## Change-set boundary

Before creating a change set, the runner verifies the account, region, stack
ID/status, original and processed templates, full parameters, complete
resource inventory, API routes, authoring function, published version and
unweighted `test` alias. The change set may contain only:

1. `Modify` with `Replacement=False` on
   `ThnContentHubV2AuthoringFunction` for its code property;
2. one new `AWS::Lambda::Version` for that exact function;
3. `Modify` with `Replacement=False` on
   `ThnContentHubV2AuthoringFunctionAliastest` to point to the new version;
4. at most one removal of the superseded authoring Version, only with
   `PolicyAction: Retain`.

The generated Version suffix is not hardcoded, but its function prefix,
resource type, version reference and count are checked against the processed
candidate and live inventory. The actual change-set actions and property
details must match these expectations; no additional resource, permission,
API, IAM, URL, table, bucket, schedule, publisher or replacement is allowed.
If the SAM transform produces a different shape, the runner stops before
execution and records a public-safe rejection code.

Immediately before execution, the runner rereads the stack identity, status,
parameters, both templates, inventory, routes and alias target. Any drift
stops the operation. The change set belongs to this run and is deleted only
when its identity is verified and it was not executed; an ambiguous failure
is retained for private diagnosis under the existing release rules.

## Post-execution and failure behavior

After execution, require `UPDATE_COMPLETE`, the same stack and protected
resource identities, unchanged shared API/permissions/other functions, one
new authoring version, an unweighted `test` alias targeting that version, and
an alias code digest matching the packaged artifact. The previous version
and package coordinates remain available for a separately reviewed rollback.
No automatic rollback or account, registry, article, or publication mutation
occurs.

The public-safe anonymous probe `POST {}` to the direct TEST authoring read
route must move from the handler's route `404` to a request-validation `400`.
This proves the path reaches payload validation without using a session or
private data. The final acceptance check uses the existing QA browser session
to load the article list; it does not create or publish an article. A later
failure is diagnosed from the next response layer before any further deploy.

## Verification

Add offline tests for exact source/artifact selection, live preconditions,
one-property template composition, full parameter preservation, all allowed
and forbidden change-set shapes, pre-execution drift, retained old version,
alias code verification, no route/permission changes, and safe failure paths.
Run the runtime and release suites, artifact allowlist, SAM/template/workflow
validation and dependency audit. A release still requires a separate explicit
approval after the implementation and actual TEST preflight are reviewed.

## Alternatives considered

- Rerun the existing `enable` operation: its package can update several
  retained THN functions and aliases, exceeding the requested scope.
- Update Lambda code and alias directly: faster for TEST, but leaves
  CloudFormation's code and version pointers behind and risks overwrite on
  a later stack update.
- Add a guarded CloudFormation `authoring-patch`: more preparation, but the
  reviewed change set and stack state make the one-function change durable.
