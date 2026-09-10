# THN SDK template mapping semantics

Date: 2026-09-10 (Central Time).

The closed registry diagnostic returned an empty difference list while its
template equality check rejected the candidate. Read-only SDK inspection and
local reproduction identified nested OrderedDict comparison as the cause:
reordering the same JSON object's keys produced inequality without any changed
content. The text/YAML Original template path already produced ordinary maps.

The THN release loader now copies SDK mappings to plain dictionaries at every
depth. It preserves every key, value, scalar type and array position, with no
input mutation or mutable aliasing. This affects only the dedicated THN release
tool, not an application handler, template, workflow, IAM policy or other draft.
All exact-resource, parameter, comparison, retention and cleanup guards remain.

Three regression tests failed before the fix and passed afterward, covering
nested input conversion, exact content comparison and the full 17+5 bootstrap
runner. Additional controls reject real list, scalar-type, missing-key,
extra-key and API changes. Source validation does not establish a successful
registry deployment or blog activation; a new reviewed artifact is required.
