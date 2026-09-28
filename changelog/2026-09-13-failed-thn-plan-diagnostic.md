# THN failed-plan diagnostic

Date: 2026-09-13 (Central Time)

The dedicated TEST lifecycle now checks the exact returned change-set identity
and a failed creation status before attempting template or parameter validation.
A non-no-op FAILED plan remains available in CloudFormation for private
diagnosis; only a static rejection code is printed. No provider reason or
private parameter value is emitted. Other cleanup and execution checks remain
unchanged, including the existing exact no-op path.

Regression tests cover missing failed-plan parameters, early rejection without
template reads, response identity substitution, available-plan cleanup and the
unchanged no-op path. Source validation is not deployment or blog activation.
