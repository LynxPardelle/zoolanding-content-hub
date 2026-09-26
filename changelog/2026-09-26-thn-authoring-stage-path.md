# THN TEST authoring stage path

After the QA account completed login and MFA, the private journal desk loaded
but its article-list request failed. An anonymous `POST {}` to both the TEST
CloudFront route and the direct HTTP API route returned the handler's 404
`not_found` / `Content hub route not found`. The request therefore reached the
authoring Lambda and failed before payload, registry, or session processing.
The TEST CloudFront origin prepends `/test`; the HTTP API uses a named `test`
stage and payload format 2.0. The stage-prefixed event path is the narrow
explanation consistent with those live responses and the handler's exact-path
comparison; the live event itself was not logged. The legacy handler in
`lambda_function.py` already strips the API Gateway stage prefix, but the v2
authoring handler did not.

The source change accepts `/test/features/content-hub-v2/read` and
`/test/features/content-hub-v2/action` only when `requestContext.stage` is
`test`, then applies the existing operation, scope, session, CSRF, and storage
checks. Canonical paths stay valid; other stages, paths, and methods remain
rejected. A new offline test reproduced both 404s before the fix and passed
after it, including the rejection cases.

Local verification: 465 runtime tests ran successfully (5 skipped), and 124
release tests passed. The first Windows run lacked Python dependencies and timezone
data; an ignored virtual environment and the installed Git timezone database
resolved those local setup errors. No AWS update, article mutation, or
publication occurred. The current dedicated TEST workflow has no authoring
code-only operation, so a reviewed release mechanism is still needed. Live
authenticated article-list behavior requires verification after that
separately approved TEST release.
