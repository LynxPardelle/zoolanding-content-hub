import json
import unittest
from unittest import mock

import content_hub_v2_authoring_handler as authoring
from test_thn_content_hub_v2_task_021_authoring import event_for


class StagePathRoutingTests(unittest.TestCase):
    def _send(self, path, operation, *, stage="test", method="POST"):
        request = event_for(path, operation)
        request["requestContext"]["stage"] = stage
        request["requestContext"]["http"]["method"] = method
        with mock.patch.object(authoring, "AwsAuthoringRuntime") as runtime:
            response = authoring.handle_request(request, object())
        runtime.assert_not_called()
        return response["statusCode"], json.loads(response["body"])["code"]

    def test_named_test_stage_accepts_only_the_two_authoring_routes(self):
        for suffix in (authoring.READ_PATH, authoring.ACTION_PATH):
            with self.subTest(path=suffix):
                self.assertEqual(
                    self._send("/test" + suffix, "unsupportedOperation"),
                    (400, "unsupported_operation"),
                )

    def test_canonical_routes_remain_valid_with_named_stage(self):
        for path in (authoring.READ_PATH, authoring.ACTION_PATH):
            with self.subTest(path=path):
                self.assertEqual(
                    self._send(path, "unsupportedOperation"),
                    (400, "unsupported_operation"),
                )

    def test_stage_prefix_does_not_open_other_paths_or_methods(self):
        cases = (
            ("/test" + authoring.READ_PATH, "prod", "POST"),
            ("/test/test" + authoring.READ_PATH, "test", "POST"),
            ("/test" + authoring.READ_PATH + "/extra", "test", "POST"),
            ("/test" + authoring.ACTION_PATH, "test", "GET"),
        )
        for path, stage, method in cases:
            with self.subTest(path=path, stage=stage, method=method):
                self.assertEqual(
                    self._send(path, "unsupportedOperation", stage=stage, method=method),
                    (404, "not_found"),
                )


if __name__ == "__main__":
    unittest.main()
