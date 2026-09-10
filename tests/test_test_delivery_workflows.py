import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STACK_NAME = "zoolanding-content-hub-test"


class TestDeliveryWorkflowContractTests(unittest.TestCase):
    def workflow(self, name: str) -> str:
        path = ROOT / ".github" / "workflows" / name
        self.assertTrue(path.is_file(), f"missing {path}")
        return path.read_text(encoding="utf-8")

    def assert_actions_are_commit_pinned(self, workflow: str) -> None:
        for value in re.findall(r"(?m)^\s*uses:\s*([^\s#]+)", workflow):
            if value.startswith("./"):
                continue
            self.assertRegex(value, r"@[a-f0-9]{40}$")

    def assert_release_boundary(self, workflow: str) -> None:
        for value in (
            "environment: test",
            "id-token: write",
            "artifact-ids:",
            "manifest_digest",
            "sha256sum",
            "recomputed-build-manifest.sha256",
            "cmp --silent",
            "create-change-set",
            "describe-change-set",
            "execute-change-set",
            "stateful_resource_change_forbidden",
            "Post-deploy smoke",
            STACK_NAME,
        ):
            self.assertIn(value, workflow)
        self.assertNotIn("sam deploy", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assert_actions_are_commit_pinned(workflow)

    def test_deploy_uses_exact_test_artifact_and_reviewed_change_set(self):
        workflow = self.workflow("deploy-test.yml")
        self.assertIn("branches: [test]", workflow)
        self.assertIn("${{ github.sha }}", workflow)
        self.assertRegex(workflow, r"\^\[a-f0-9\]\{40\}\$")
        self.assert_release_boundary(workflow)

    def test_rollback_selects_one_recorded_immutable_release(self):
        workflow = self.workflow("rollback-test.yml")
        for value in (
            "workflow_dispatch:",
            "source_run_id:",
            "source_artifact_id:",
            "source_sha:",
            "source_manifest_sha256:",
            "run-id:",
            "refs/heads/test",
            "getWorkflowRun",
        ):
            self.assertIn(value, workflow)
        self.assert_release_boundary(workflow)

    def test_both_workflows_forward_selection_and_verify_cloud_before_changes(self):
        for name in ("deploy-test.yml", "rollback-test.yml"):
            with self.subTest(name=name):
                workflow = self.workflow(name)
                self.assertEqual(workflow.count("THN_V2_TEST_PARAMETERS_JSON: ${{ vars.THN_V2_TEST_PARAMETERS_JSON }}"), 2)
                self.assertIn("prepare_test_parameters.py --verify-cloud-guards", workflow)
                self.assertIn("if: ${{ vars.THN_V2_TEST_PARAMETERS_JSON != '' }}", workflow)
                self.assertIn('if [ -n "${THN_V2_TEST_PARAMETERS_JSON:-}" ]; then', workflow)
                self.assertIn('"thn-test-selection/v1"', workflow)
                self.assertIn('thn_test_selection_contract_missing', workflow)
                self.assertLess(workflow.index("prepare_test_parameters.py --thn-selection-contract"),
                                workflow.index("uses: aws-actions/configure-aws-credentials@"))
                credentials = workflow.index("uses: aws-actions/configure-aws-credentials@")
                guard = workflow.index("prepare_test_parameters.py --verify-cloud-guards")
                execute = workflow.index("run: bash .aws-sam/build/release-tools/run_test_change_set.sh")
                self.assertLess(credentials, guard)
                self.assertLess(guard, execute)


if __name__ == "__main__":
    unittest.main()
