# THN first-provisioning condition closure

2026-09-13, Central Time.

The dedicated template composer copied `IsThnContentHubV2*` conditions but omitted
the exact `HasThnContentHubV2EmergencyOperatorRole` declaration. First provisioning
therefore produced two unresolved condition references when the prior shared
template had no THN conditions. Source-template-only checks did not exercise
this composed-template case.

The narrow correction copies that one existing declaration without changing its
expression, policies, shared template, route controls or disabled defaults.
A regression starts from a THN-free baseline, verifies both reference targets,
retains shared conditions, rejects an unrelated `HasThn*` addition and checks
input immutability. Reproduce RED before applying the correction; native composed
validation and full runtime/release checks remain release prerequisites.

This source change is not evidence of deployment or client access activation.
