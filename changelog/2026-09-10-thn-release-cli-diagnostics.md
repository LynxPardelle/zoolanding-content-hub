# THN release CLI diagnostic correction

Date: 2026-09-10 (Central Time).

- The file entrypoint now delegates to the package's `main`, keeping the CLI
  and registry helpers on the same `ReleaseBlocked` class.
- Static change-set review rejections retain their specific error code and
  nonzero exit; unknown/provider errors still expose no exception details.
- Five regression tests cover the real file entrypoint, transported tools,
  reviewer rejection and both provider and unexpected-error redaction. Three
  tests reproduced the missing diagnostic before the minimal correction.
- Templates, workflow files, IAM, runtime code, routes and activation controls
  are unchanged. Source preparation is not evidence of a successful bootstrap.
