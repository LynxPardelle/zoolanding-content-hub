"""Every runtime test job installs its declared template-test dependencies."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class TestDependencies(unittest.TestCase):
    def test_test_jobs_install_release_dependencies_before_running_suites(self):
        names = (
            "ci.yml", "offline-tests.yml", "validate-thn-candidate.yml",
            "deploy-test.yml", "deploy-thn-test.yml", "validate-thn-release.yml",
        )
        for name in names:
            workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
            for job_name, job in workflow["jobs"].items():
                script = "\n".join(step.get("run", "") for step in job.get("steps", []))
                if "-m unittest discover" not in script:
                    continue
                with self.subTest(workflow=name, job=job_name):
                    before_tests = script.split("-m unittest discover", 1)[0]
                    self.assertIn("-r requirements-release.txt", before_tests)

    def test_offline_job_keeps_network_and_credential_isolation(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/offline-tests.yml").read_text())
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        job = workflow["jobs"]["offline-tests"]
        self.assertNotIn("environment", job)
        script = "\n".join(step.get("run", "") for step in job["steps"])
        self.assertIn("sudo -- unshare --net -- env -i", script)
        self.assertIn("AWS_SHARED_CREDENTIALS_FILE=/dev/null", script)
        self.assertIn("AWS_CONFIG_FILE=/dev/null", script)
        self.assertNotIn("configure-aws-credentials", str(job))


if __name__ == "__main__":
    unittest.main()
