"""The real release entrypoint preserves safe failures, never provider details."""

import contextlib
import io
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from botocore.exceptions import ClientError
from tools import review_test_change_set

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "tools/thn_test_release.py"
GENERIC = "thn_test_release_failed; access remains subject to the independent registry gate\n"


class ReleaseCliDiagnosticTests(unittest.TestCase):
    def _invalid_context(self, entry, cwd):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("AWS_", "GITHUB_", "THN_", "EXPECTED_"))
               and key not in {"ARTIFACTS_BUCKET", "PYTHONPATH"}}
        env.update(AWS_EC2_METADATA_DISABLED="true",
                   AWS_CONFIG_FILE=str(Path(cwd) / "absent-config"),
                   AWS_SHARED_CREDENTIALS_FILE=str(Path(cwd) / "absent-credentials"))
        return subprocess.run([sys.executable, str(entry), "--operation", "registry-provision"],
                              cwd=cwd, env=env, text=True, capture_output=True,
                              timeout=20, check=False)

    def _assert_context_denied(self, result):
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "test_release_context_invalid\n")

    def test_file_entrypoint_reports_real_registry_context_denial(self):
        with tempfile.TemporaryDirectory(prefix="thn-cli-context-") as temporary:
            self._assert_context_denied(self._invalid_context(ENTRY, temporary))

    def test_transported_entrypoint_keeps_the_same_safe_diagnostic(self):
        with tempfile.TemporaryDirectory(prefix="thn-cli-transport-") as temporary:
            target = Path(temporary)
            (target / "tools").mkdir()
            for name in ("__init__.py", "thn_test_release.py", "prepare_test_parameters.py",
                         "review_test_change_set.py", "thn_api_boundary.py", "thn_registry_provision.py"):
                shutil.copyfile(ROOT / "tools" / name, target / "tools" / name)
            self._assert_context_denied(self._invalid_context(target / "tools/thn_test_release.py", target))

    def _main_failure(self, effect):
        # Only the deployment boundary is replaced; no real cloud action may run.
        entry = runpy.run_path(str(ENTRY), run_name="thn_cli_diagnostic_test")
        output, errors = io.StringIO(), io.StringIO()
        with patch.dict(entry["main"].__globals__, {"run_release": effect}), \
                patch("boto3.Session", return_value=object()), \
                patch.object(sys, "argv", [str(ENTRY), "--operation", "registry-provision"]), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = entry["main"]()
        self.assertEqual(code, 1)
        self.assertEqual(output.getvalue(), "")
        return errors.getvalue()

    def test_change_set_reviewer_preserves_its_static_rejection_code(self):
        def reject(*args, **kwargs):
            review_test_change_set._parameter_map(None)
        self.assertEqual(self._main_failure(reject), "change_set_parameters_invalid\n")

    def test_provider_exception_does_not_expose_message_or_response(self):
        def fail(*args, **kwargs):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "private-provider-sentinel"},
                               "ResponseMetadata": {"RequestId": "private-request-sentinel"}}, "GetTemplate")
        self.assertEqual(self._main_failure(fail), GENERIC)

    def test_unexpected_exception_does_not_expose_its_details(self):
        def fail(*args, **kwargs):
            raise ValueError("private-unexpected-sentinel")
        self.assertEqual(self._main_failure(fail), GENERIC)


if __name__ == "__main__":
    unittest.main()
