"""TEST source promotion cannot execute AWS or masquerade as a release."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SERVICE = "zoolanding-content-hub"
SHA = "a" * 40
RUN = "12345"
ATTEMPT = "2"


class TestValidationOnly(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (ROOT / ".github/workflows/deploy-test.yml").read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.text)
        cls.rollback = yaml.safe_load(
            (ROOT / ".github/workflows/rollback-test.yml").read_text(encoding="utf-8")
        )

    def python_block(self, script):
        match = re.search(r"<<'PY'\n(.*?)\nPY(?:\n|$)", script, re.DOTALL)
        self.assertIsNotNone(match, "real workflow Python block must exist")
        return match.group(1)

    def validation_verifier(self):
        jobs = self.workflow["jobs"]
        job = jobs.get("verify-artifact", jobs.get("deploy"))
        return next(step["run"] for step in job["steps"]
                    if step.get("name") == "Verify transported artifact and source identity")

    def run_metadata_code(self, script, payload=None, arguments=()):
        with tempfile.TemporaryDirectory(prefix="hub-validation-contract-") as temporary:
            target = Path(temporary) / ".aws-sam/build/release-metadata.json"
            target.parent.mkdir(parents=True)
            if payload is not None:
                target.write_text(json.dumps(payload), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-c", self.python_block(script), *arguments],
                cwd=temporary,
                env={**os.environ, "RELEASE_SHA": SHA, "SERVICE_ID": SERVICE,
                     "GITHUB_RUN_ID": RUN, "GITHUB_RUN_ATTEMPT": ATTEMPT},
                capture_output=True, text=True, check=False,
            )
            actual = json.loads(target.read_text(encoding="utf-8")) if target.exists() else None
            return result, actual

    def metadata(self):
        return {"schema": "zoolanding-test-validation/v1", "purpose": "validation-only",
                "deployable": False, "service": SERVICE, "source_sha": SHA,
                "run_id": RUN, "run_attempt": ATTEMPT}

    def test_only_unprivileged_validation_jobs_exist(self):
        self.assertEqual(set(self.workflow["jobs"]), {"validate", "verify-artifact"})
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        for name, job in self.workflow["jobs"].items():
            with self.subTest(job=name):
                self.assertNotIn("environment", job)
                self.assertEqual(job["permissions"], {"contents": "read"})
        for forbidden in ("id-token:", "${{ secrets.", "${{ vars.",
                          "configure-aws-credentials@", "run_test_change_set.sh",
                          "smoke_test_stack.sh", "release-tools", "sam deploy", "sam package"):
            self.assertTrue(forbidden not in self.text, f"forbidden validation capability: {forbidden}")
        self.assertIsNone(re.search(r"(?m)^\s*aws\s+", self.text))

    def test_both_suites_run_before_the_build(self):
        step = next(item for item in self.workflow["jobs"]["validate"]["steps"]
                    if item.get("name") == "Test, validate, and build exact source")
        script = step["run"]
        for command in ('unittest discover -s tests -p "test_*.py"',
                        'unittest discover -s tests_release -p "test_*.py"'):
            self.assertTrue(command in script, f"required suite missing: {command}")
            self.assertLess(script.index(command), script.index("sam build"))

    def test_exact_promotion_and_transport_guards_remain(self):
        for marker in ("branches: [test]", 'test "$GITHUB_REF" = "refs/heads/test"',
                       'test "$PUSH_FORCED" != "true"', 'test "$first_parent" = "$BEFORE_SHA"',
                       'test "$second_parent" = "$(git rev-parse refs/remotes/origin/dev)"',
                       'test -z "${extra:-}"', "HEAD^{tree}", "refs/remotes/origin/dev^{tree}",
                       "artifact-ids: ${{ needs.validate.outputs.artifact_id }}",
                       "find .aws-sam -type l", "recomputed-build-manifest.sha256",
                       "cmp --silent", "sha256sum --check --strict"):
            self.assertTrue(marker in self.text, f"required guard missing: {marker}")
        for action in re.findall(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)", self.text):
            self.assertRegex(action, r"@[a-f0-9]{40}$")

    def test_name_and_summary_cannot_imply_a_deployment(self):
        self.assertEqual(self.workflow["name"], "Validate Test promotion (no deploy)")
        self.assertTrue(SERVICE + "-test-validation-" in self.text)
        self.assertTrue("not a deployment or rollback artifact" in self.text)

    def test_real_writer_emits_only_validation_metadata(self):
        script = next(step["run"] for step in self.workflow["jobs"]["validate"]["steps"]
                      if "write_text" in step.get("run", ""))
        result, metadata = self.run_metadata_code(script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(metadata, self.metadata())
        self.assertIs(metadata["deployable"], False)

    def test_real_verifier_accepts_exact_validation_metadata(self):
        result, _ = self.run_metadata_code(self.validation_verifier(), self.metadata(),
                                           (SHA, SERVICE, RUN, ATTEMPT))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_real_verifier_rejects_changed_or_missing_fields(self):
        script = self.validation_verifier()
        replacements = {"schema": "zoolanding-test-release/v1", "purpose": "release",
                        "deployable": True, "service": "another-service", "source_sha": "b" * 40,
                        "run_id": "99999", "run_attempt": "1"}
        for key, value in replacements.items():
            for missing in (True, False):
                payload = self.metadata()
                if missing:
                    del payload[key]
                else:
                    payload[key] = value
                with self.subTest(field=key, missing=missing):
                    result, _ = self.run_metadata_code(script, payload, (SHA, SERVICE, RUN, ATTEMPT))
                    self.assertNotEqual(result.returncode, 0)
        for value in (0, "false", None):
            with self.subTest(deployable=value):
                payload = {**self.metadata(), "deployable": value}
                result, _ = self.run_metadata_code(script, payload, (SHA, SERVICE, RUN, ATTEMPT))
                self.assertNotEqual(result.returncode, 0)

    def test_verifier_receives_its_own_run_and_attempt(self):
        script = self.validation_verifier()
        self.assertTrue('"$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"' in script)

    def test_historical_rollback_rejects_validation_before_credentials(self):
        steps = self.rollback["jobs"]["rollback"]["steps"]
        index = next(i for i, step in enumerate(steps)
                     if step.get("name") == "Verify recorded artifact, digest, and source")
        credentials = next(i for i, step in enumerate(steps)
                           if step.get("uses", "").startswith("aws-actions/configure-aws-credentials@"))
        self.assertLess(index, credentials)
        script = steps[index]["run"]
        result, _ = self.run_metadata_code(script, self.metadata(), (RUN, SHA, SERVICE))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release_metadata_invalid", result.stderr)
        historical = {"schema": "zoolanding-test-release/v1", "service": SERVICE,
                      "source_sha": SHA, "run_id": RUN, "run_attempt": ATTEMPT}
        result, _ = self.run_metadata_code(script, historical, (RUN, SHA, SERVICE))
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
