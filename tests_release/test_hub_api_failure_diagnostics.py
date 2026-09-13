"""The real runner retains only its rejected API plan and emits fixed reasons."""
from copy import deepcopy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from tools import thn_test_release as release
import test_hub_failed_change_set as failed
from test_hub_lifecycle_runner import LifecycleCloud
from test_thn_test_release import ACCOUNT


class ApiFailureCloud(LifecycleCloud):
    def __init__(self, failure):
        super().__init__()
        self.failure = failure

    def native(self, template):
        result = super().native(template)
        if self.failure == "api":
            result["Resources"]["ContentHubApi"]["Properties"]["Description"] = "private-api-sentinel"
        elif self.failure == "permission":
            result["Resources"]["ThnContentHubV2AuthoringFunctionReadPermission"]["Metadata"] = {
                "private-key-sentinel": "private-value-sentinel"}
        return result


class ApiFailureDiagnosticTests(unittest.TestCase):
    def run_cloud(self, cloud):
        fixture = failed.HubFailedChangeSetTests(); fixture.setUp()
        with patch.object(release, "ACCOUNT_HASH", hashlib.sha256(ACCOUNT.encode()).hexdigest()), \
                patch.object(release, "_package_template", return_value=cloud.source), \
                patch.object(release.time, "sleep"):
            return release.run_release(cloud, fixture.env, Path("unused-build"), "provision")

    def assert_rejected(self, cloud, reason):
        previous = deepcopy((cloud.original, cloud.processed, cloud.stack))
        with self.assertRaises(release.ReleaseBlocked) as failure:
            self.run_cloud(cloud)
        self.assertEqual(str(failure.exception),
            "processed_shared_api_boundary_mismatch; reason=" + reason + "; diagnostic_retained")
        self.assertFalse(cloud.executed)
        self.assertFalse(any(name == "delete_change_set" for name, _ in cloud.calls))
        self.assertEqual((cloud.original, cloud.processed, cloud.stack), previous)
        self.assertTrue(any(name == "get_template" and args.get("ChangeSetName") == cloud.change_id
                            and args.get("TemplateStage") == "Processed" for name, args in cloud.calls))

    def test_actual_api_drift_has_fixed_reason_and_never_executes(self):
        self.assert_rejected(ApiFailureCloud("api"), "shared_api_nonbody_field_changed")

    def test_actual_permission_drift_has_fixed_reason_without_private_fields(self):
        self.assert_rejected(ApiFailureCloud("permission"), "exact_thn_http_permission_mismatch")

    def test_unclassified_boundary_exception_never_reflects_its_message(self):
        with patch.object(release.thn_api_boundary, "verify_route_permissions",
                          side_effect=release.thn_api_boundary.ApiBoundaryError("private-exception-sentinel")):
            self.assert_rejected(ApiFailureCloud("none"), "unclassified")

    def test_unrelated_processed_drift_still_cleans_only_its_owned_plan(self):
        cloud = ApiFailureCloud("none"); cloud.corrupt_shared = True
        with self.assertRaisesRegex(release.ReleaseBlocked, "^processed_shared_resource_drift$"):
            self.run_cloud(cloud)
        self.assertFalse(cloud.executed)
        self.assertEqual([args for name, args in cloud.calls if name == "delete_change_set"],
            [{"StackName": release.STACK, "ChangeSetName": cloud.change_id}])


if __name__ == "__main__":
    unittest.main()
