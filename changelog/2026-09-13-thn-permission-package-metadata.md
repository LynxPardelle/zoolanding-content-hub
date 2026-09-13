# THN permission packaging metadata

2026-09-13, Central Time (UTC-06:00).

The dedicated TEST diagnostic established that the three explicit THN invoke
permissions matched every expected property and condition but carried SAM's
exact self-identifying `SamResourceId` annotation after packaging. Translation
of the exact packaged template reproduced the provider's native representation.

The closed validator now accepts only the original exact contract or that same
contract plus the permission's own single metadata entry. It does not discard
arbitrary metadata, mutate templates, widen invocation authority or modify
shared routes. Tests reject foreign IDs, extra/malformed metadata and changed
properties/conditions, and cover packaged source through the lifecycle runner.

Two regressions reproduced the rejection before the correction. This source
change does not prove AWS deployment, registry activation or customer access;
the dedicated TEST workflow and its postchecks remain mandatory.
