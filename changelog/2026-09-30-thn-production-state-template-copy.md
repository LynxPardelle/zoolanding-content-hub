# THN production state template isolation

Protected Content Hub state review `36791478935` stopped before execution with
`production_general_change_requires_own_review`. Its native preview contained
the intended additions and Registry policy update, but also proposed updating
the historical `ContentHubFunction` code. That update caused derived changes to
the public API and scheduling resources. The release guard correctly rejected
the preview; the production stack remained unchanged.

CloudFormation returned its Original template as a mutable mapping. The state
candidate reused historical resource and parameter mappings by reference.
Later, the review replaced the historical Lambda `CodeUri` in that same mapping
with a sealed recovery coordinate, unintentionally changing the candidate.
The candidate now deep-copies preserved declarations before recovery sealing.
No inventory or permission guard has been relaxed.

A regression test reproduced the reference mutation before the fix and passed
afterward. The full local suite passed 552 tests with five skips. A read-only
snapshot of the production stack and local SAM translation, including the
recovery mutation, preserved the 21 existing resources except for the intended
Registry policy change and projected 44 new native logical resources. This
change requires a new protected review after code promotion; the failed change
set must not be executed.
