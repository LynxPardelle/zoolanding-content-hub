import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.review_test_change_set import ChangeSetReviewError, review_change_set


ARN = "arn:aws:cloudformation:us-east-1:123456789012:changeSet/release-1/abc"


def payload(*, action="Modify", replacement="False"):
    return {"StackName": "example-test", "ChangeSetName": "release-1", "ChangeSetId": ARN, "Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE", "Parameters": [{"ParameterKey": "EnvironmentName", "ParameterValue": "test"}, {"ParameterKey": "EnableFeature", "ParameterValue": "false"}], "Changes": [{"Type": "Resource", "ResourceChange": {"Action": action, "Replacement": replacement}}]}


class ReviewTestChangeSetTests(unittest.TestCase):
    def test_accepts_exact_nonreplacement_update(self):
        self.assertEqual(review_change_set(payload(), expected_stack_name="example-test", expected_change_set_name="release-1", expected_change_set_arn=ARN, expected_change_set_type="UPDATE", expected_parameters={"EnvironmentName": "test", "EnableFeature": "false"}, required_parameters=set()), "execute")


    def test_accepts_exact_create_without_describe_type(self):
        self.assertEqual(
            review_change_set(
                payload(action="Add", replacement=None),
                expected_stack_name="example-test",
                expected_change_set_name="release-1",
                expected_change_set_arn=ARN,
                expected_change_set_type="CREATE",
                expected_parameters={"EnvironmentName": "test"},
                required_parameters=set(),
            ),
            "execute",
        )

    def test_accepts_exact_noop_without_describe_type(self):
        candidate = payload()
        candidate.update(
            Status="FAILED", ExecutionStatus="UNAVAILABLE", Changes=[],
            StatusReason="The submitted information didn't contain changes. "
            "Submit different information to create a change set.",
        )
        self.assertEqual(
            review_change_set(
                candidate, expected_stack_name="example-test",
                expected_change_set_name="release-1", expected_change_set_arn=ARN,
                expected_change_set_type="UPDATE",
                expected_parameters={"EnvironmentName": "test"},
                required_parameters=set(),
            ),
            "noop",
        )

    def test_rejects_invalid_creation_type(self):
        with self.assertRaisesRegex(ChangeSetReviewError, "change_set_type_invalid"):
            review_change_set(
                payload(), expected_stack_name="example-test",
                expected_change_set_name="release-1", expected_change_set_arn=ARN,
                expected_change_set_type="IMPORT", expected_parameters={},
                required_parameters=set(),
            )

    def test_rejects_optional_type_mismatch(self):
        for reported_type in ("CREATE", "IMPORT", None):
            candidate = payload()
            candidate["ChangeSetType"] = reported_type
            with self.subTest(reported_type=reported_type):
                with self.assertRaisesRegex(ChangeSetReviewError, "change_set_identity_invalid"):
                    review_change_set(
                        candidate, expected_stack_name="example-test",
                        expected_change_set_name="release-1", expected_change_set_arn=ARN,
                        expected_change_set_type="UPDATE", expected_parameters={},
                        required_parameters=set(),
                    )

    def test_accepts_matching_optional_type(self):
        candidate = payload()
        candidate["ChangeSetType"] = "UPDATE"
        self.assertEqual(
            review_change_set(
                candidate, expected_stack_name="example-test",
                expected_change_set_name="release-1", expected_change_set_arn=ARN,
                expected_change_set_type="UPDATE", expected_parameters={},
                required_parameters=set(),
            ),
            "execute",
        )

    def test_rejects_identity_drift_without_describe_type(self):
        for field in ("StackName", "ChangeSetName", "ChangeSetId"):
            candidate = payload()
            candidate[field] = "unexpected"
            with self.subTest(field=field):
                with self.assertRaisesRegex(ChangeSetReviewError, "change_set_identity_invalid"):
                    review_change_set(
                        candidate, expected_stack_name="example-test",
                        expected_change_set_name="release-1", expected_change_set_arn=ARN,
                        expected_change_set_type="UPDATE", expected_parameters={},
                        required_parameters=set(),
                    )

    def test_runner_binds_create_request_and_review_to_same_type(self):
        runner = (ROOT / "tools" / "run_test_change_set.sh").read_text(encoding="utf-8")
        self.assertIn('--change-set-type "$change_set_type"', runner)
        self.assertIn('--expected-change-set-type "$change_set_type"', runner)

    def test_rejects_remove_and_replacement(self):
        for candidate in (payload(action="Remove"), payload(replacement="True")):
            with self.subTest(candidate=candidate), self.assertRaisesRegex(ChangeSetReviewError, "stateful_resource_change_forbidden"):
                review_change_set(candidate, expected_stack_name="example-test", expected_change_set_name="release-1", expected_change_set_arn=ARN, expected_change_set_type="UPDATE", expected_parameters={"EnvironmentName": "test"}, required_parameters=set())

    def test_rejects_parameter_drift(self):
        with self.assertRaises(ChangeSetReviewError):
            review_change_set(payload(), expected_stack_name="example-test", expected_change_set_name="release-1", expected_change_set_arn=ARN, expected_change_set_type="UPDATE", expected_parameters={"EnableFeature": "true"}, required_parameters=set())


if __name__ == "__main__":
    unittest.main()
