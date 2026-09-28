# Test template dependencies

Date: 2026-09-09 (Central Time).

The merged candidate's isolated-network test job lacked PyYAML, required by
the editor's template permission tests. Install the existing pinned release
requirements before running the suite in CI, candidate validation, TEST build
validation and the offline environment. Do not add PyYAML to Lambda packages.

The regression test first failed for all four missing install sites. It also
checks that the offline job retains its network namespace, empty credential
files and read-only permissions. Runtime source, permissions, activation
defaults, production deployment workflow and network isolation are unchanged.
