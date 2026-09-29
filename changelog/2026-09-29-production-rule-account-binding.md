# Production Content Hub Rules account binding

Production state review run 36612383287 failed while CloudFormation created its change set. The provider retained the failed preview and reported `Template format error: Following functions are not supported in the Rules block of the template: [Fn::Sub]`. The stack was not updated; Image Upload review was held as approved.

The production projection converted the TEST emergency operator role name but left its account-scoped `Fn::Sub` inside `Rules`. CloudFormation rejects that intrinsic even when the activation rule is false. Bind the exact production operator ARN to the reviewed account literal during offline projection and reject changed operands or other unsupported Rules functions before packaging.

The regression test first failed with the provider-invalid `Fn::Sub`, then passed with the literal. All 518 runtime tests (5 skips), 134 release tests, SAM basic validation, cfn-lint, and a read-only AWS `ValidateTemplate` of the projected Rules passed. The next production review must use a new MAIN source SHA; the failed preview cannot authorize execution.
