# THN Rules account binding

Date: 2026-09-13 (Central Time)

CloudFormation rejected the dedicated composed template because Rules do not
support Fn::Sub. The release runner now compiles only the existing exact
emergency-role equality operand using the already verified TEST STS identity.
It preserves the full assertion and every other template node. Already bound
identical literals remain valid for retained disablement; different accounts,
roles and assertion shapes fail closed before upload.

No IAM, template source, parameter contract, generic workflow, handler, writer
or public route changed. Unit tests cover the exact compiled equality, immutable
inputs, supported Rules intrinsics, idempotence, rejected substitutions and the
actual runner's uploaded template. Source validation is not blog activation.
