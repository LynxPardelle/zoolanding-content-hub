"""Release-only suite: the shared API exception is exactly three path subtrees."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/fixtures/thn_release_api_baseline.json").read_text())
PAIRS = ("Authoring", "PrivateAssetCollector", "Publisher", "PublicMedia", "InvalidationWorker", "EmergencyWithdraw", "PreparedOrphanCollector")


class SharedApiBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.template = yaml.safe_load((ROOT / "template.yaml").read_text())
        path = ROOT / "tools/thn_api_boundary.py"
        self.assertTrue(path.is_file(), "Exact shared-API boundary is missing")
        spec = importlib.util.spec_from_file_location("hub_api_boundary", path)
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)
        self.live = {"Resources": {"ContentHubApi": deepcopy(FIXTURE["api"])}}
        self.candidate = deepcopy(self.live)
        self.inventory = {"ContentHubApi": {"ResourceType": "AWS::ApiGatewayV2::Api", "PhysicalResourceId": "abc123tes0"}}
        self.change = {"LogicalResourceId": "ContentHubApi", "ResourceType": "AWS::ApiGatewayV2::Api",
            "PhysicalResourceId": "abc123tes0", "Action": "Modify", "Replacement": "False", "Scope": ["Properties"],
            "Details": [{"Target": {"Attribute": "Properties", "Name": "Body", "RequiresRecreation": "Never"}}]}

    def test_exact_seven_runtime_role_pairs_survive_disable(self):
        for pair in PAIRS:
            for suffix in ("Function", "Role"):
                self.assertEqual(self.template["Resources"]["ThnContentHubV2" + pair + suffix]["Condition"], "IsThnContentHubV2StateProvisioned")

    def test_source_routes_have_identical_methods_integrations_auth_and_permissions(self):
        body = self.template["Resources"]["ContentHubApi"]["Properties"]["DefinitionBody"]
        self.assertEqual(set(body["paths"]), set(self.tool.PATHS))
        for path in self.tool.PATHS:
            self.assertEqual(self.tool.normalize_path(body["paths"][path]), self.tool.normalize_path(FIXTURE["api"]["Properties"]["Body"]["paths"][path]))
        for logical, original in FIXTURE["permissions"].items():
            source = deepcopy(self.template["Resources"][logical])
            source["Properties"]["FunctionName"]["Ref"] = source["Properties"]["FunctionName"]["Ref"].replace(".Alias", "Aliastest")
            self.assertEqual(source, original)
        for pair in ("Authoring", "PublicMedia"):
            self.assertNotIn("Events", self.template["Resources"]["ThnContentHubV2" + pair + "Function"]["Properties"])

    def test_exact_same_api_and_three_subtrees_are_accepted(self):
        self.tool.review_shared_api(self.change, self.live, self.candidate, self.inventory)

    def test_missing_either_verified_snapshot_fails_closed(self):
        for live, candidate in ((None, self.candidate), (self.live, None), ({}, self.candidate)):
            with self.assertRaises(self.tool.ApiBoundaryError):
                self.tool.review_shared_api(self.change, live, candidate, self.inventory)

    def test_one_v1_field_change_fails(self):
        self.candidate["Resources"]["ContentHubApi"]["Properties"]["Body"]["paths"]["/features/content-hub/read"]["post"]["responses"]["200"] = {}
        with self.assertRaises(self.tool.ApiBoundaryError):
            self.tool.review_shared_api(self.change, self.live, self.candidate, self.inventory)

    def test_extra_paths_or_methods_fail(self):
        for extra_path in ("/features/content-hub-v2/extra", "/anything"):
            candidate = deepcopy(self.candidate)
            candidate["Resources"]["ContentHubApi"]["Properties"]["Body"]["paths"][extra_path] = {"get": {}}
            with self.assertRaises(self.tool.ApiBoundaryError):
                self.tool.review_shared_api(self.change, self.live, candidate, self.inventory)
        candidate = deepcopy(self.candidate)
        route = candidate["Resources"]["ContentHubApi"]["Properties"]["Body"]["paths"][self.tool.PATHS[0]]
        route["Fn::If"][1]["delete"] = {}
        with self.assertRaises(self.tool.ApiBoundaryError):
            self.tool.review_shared_api(self.change, self.live, candidate, self.inventory)

    def test_auth_cors_host_and_api_properties_fail(self):
        for key, value in (("host", "evil.example"), ("security", [{"new": []}]), ("x-amazon-apigateway-cors", {"allowOrigins": ["*"]})):
            candidate = deepcopy(self.candidate)
            candidate["Resources"]["ContentHubApi"]["Properties"]["Body"][key] = value
            with self.subTest(key=key), self.assertRaises(self.tool.ApiBoundaryError):
                self.tool.review_shared_api(self.change, self.live, candidate, self.inventory)
        self.candidate["Resources"]["ContentHubApi"]["Properties"]["ApiKeySelectionExpression"] = "$request.header.key"
        with self.assertRaises(self.tool.ApiBoundaryError):
            self.tool.review_shared_api(self.change, self.live, self.candidate, self.inventory)

    def test_physical_identity_replacement_or_nonbody_target_fails(self):
        for mutation in ({"PhysicalResourceId": "other12345"}, {"Replacement": "True"}, {"Action": "Add"},
                         {"Details": []}, {"Details": [{"Target": {"Attribute": "Properties", "Name": "CorsConfiguration", "RequiresRecreation": "Never"}}]}):
            with self.subTest(mutation=mutation), self.assertRaises(self.tool.ApiBoundaryError):
                self.tool.review_shared_api({**self.change, **mutation}, self.live, self.candidate, self.inventory)

    def test_thn_route_integration_payload_auth_timeout_or_function_change_fails(self):
        for key, value in (("httpMethod", "GET"), ("payloadFormatVersion", "1.0"), ("timeoutInMillis", 1000), ("uri", "https://evil.example")):
            candidate = deepcopy(self.candidate)
            integration = candidate["Resources"]["ContentHubApi"]["Properties"]["Body"]["paths"][self.tool.PATHS[0]]["Fn::If"][1]["post"]["Fn::If"][1]["x-amazon-apigateway-integration"]
            integration[key] = value
            with self.subTest(key=key), self.assertRaises(self.tool.ApiBoundaryError):
                self.tool.review_shared_api(self.change, self.live, candidate, self.inventory)

    def test_composer_seeds_every_non_thn_field_from_verified_live_body(self):
        result = self.tool.compose_body(self.template, self.live)
        before = deepcopy(FIXTURE["api"]["Properties"]["Body"])
        for path in self.tool.PATHS:
            before["paths"].pop(path)
        after = deepcopy(result)
        for path in self.tool.PATHS:
            after["paths"].pop(path)
        self.assertEqual(before, after)

    def test_processed_http_permissions_cannot_widen_source_or_target(self):
        self.assertTrue(hasattr(self.tool, "verify_route_permissions"), "Exact permission validator is missing")
        processed = {"Resources": deepcopy(FIXTURE["permissions"])}
        self.tool.verify_route_permissions(processed)
        key = "ThnContentHubV2AuthoringFunctionReadPermission"
        processed["Resources"][key]["Properties"]["SourceArn"] = "*"
        with self.assertRaises(self.tool.ApiBoundaryError):
            self.tool.verify_route_permissions(processed)

    def test_composer_rejects_candidate_global_body_injection(self):
        for key, value in (("host", "evil.example"), ("security", []), ("x-amazon-apigateway-cors", {})):
            candidate = deepcopy(self.template)
            candidate["Resources"]["ContentHubApi"]["Properties"]["DefinitionBody"][key] = value
            with self.subTest(key=key), self.assertRaises(self.tool.ApiBoundaryError):
                self.tool.compose_body(candidate, self.live)


if __name__ == "__main__":
    unittest.main()
