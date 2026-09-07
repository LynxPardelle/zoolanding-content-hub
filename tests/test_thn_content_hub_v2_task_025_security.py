import re
import unittest
from pathlib import Path

from tests.test_thn_content_hub_v2_task_019_template import (
    FUNCTIONS,
    STATEFUL_RESOURCES,
    _resource,
    _statement,
    _template,
)


class ThnContentHubV2Task025SecurityTests(unittest.TestCase):
    def test_seven_functions_use_seven_distinct_handlers_roles_and_names(self):
        template = _template()
        handlers = set()
        role_ids = set()
        role_names = set()

        for function_id, (role_id, role_name, handler) in FUNCTIONS.items():
            function = _resource(template, function_id)
            role = _resource(template, role_id)
            handlers.add(handler)
            role_ids.add(role_id)
            role_names.add(role_name)
            self.assertIn(f"Handler: {handler}", function)
            self.assertIn(f"RoleName: {role_name}", role)
            self.assertRegex(
                function,
                rf"(?ms)Role:\s*\n\s+Fn::GetAtt:\s*\n"
                rf"\s+- {re.escape(role_id)}\s*\n\s+- Arn",
            )

        self.assertEqual(len(handlers), 7)
        self.assertEqual(len(role_ids), 7)
        self.assertEqual(len(role_names), 7)

    def test_only_authoring_and_public_media_have_http_routes(self):
        template = _template()
        routed = set()
        for function_id in FUNCTIONS:
            function = _resource(template, function_id)
            if "Type: HttpApi" in function:
                routed.add(function_id)

        self.assertEqual(
            routed,
            {
                "ThnContentHubV2AuthoringFunction",
                "ThnContentHubV2PublicMediaFunction",
            },
        )
        for function_id in set(FUNCTIONS) - routed:
            function = _resource(template, function_id)
            self.assertNotIn("Type: HttpApi", function)
            self.assertNotIn("FunctionUrlConfig", function)

        for function_id in (
            "ThnContentHubV2PrivateAssetCollectorFunction",
            "ThnContentHubV2InvalidationWorkerFunction",
            "ThnContentHubV2PreparedOrphanCollectorFunction",
        ):
            function = _resource(template, function_id)
            self.assertIn("Type: Schedule", function)
            self.assertIn("Enabled: false", function)

        for function_id in (
            "ThnContentHubV2PublisherFunction",
            "ThnContentHubV2EmergencyWithdrawFunction",
        ):
            self.assertNotIn("Events:", _resource(template, function_id))

    def test_authoring_cannot_write_or_read_the_public_projection(self):
        role = _resource(_template(), "ThnContentHubV2AuthoringRole")

        self.assertNotIn("ContentHubMetadataTable", role)
        self.assertNotIn("ContentHubPackagesBucket", role)
        self.assertNotIn("HUB#thehairnarrative-com-journal", role)
        self.assertNotIn("SLUG#test#thehairnarrative.com", role)
        self.assertNotIn("LIVE_MEDIA#", role)

    def test_publisher_scope_excludes_auth_and_other_tenants(self):
        role = _resource(_template(), "ThnContentHubV2PublisherRole")
        private_read = _statement(role, "ReadExactThnPrivatePublication")
        private_package = _statement(role, "ReadExactThnPrivatePackage")
        public_write = _statement(role, "FinalizeExactThnProjection")

        self.assertIn("ThnContentHubV2MetadataTable", private_read)
        self.assertNotIn("zoolanding-auth-admin", role)
        self.assertNotIn("ThnSessionV2", role)
        self.assertNotIn("ThnCurrentUserStateV2", role)
        self.assertEqual(private_package.count("s3:GetObject"), 1)
        self.assertIn(
            "${ThnContentHubV2PrivateStore.Arn}/private/test/"
            "thehairnarrative.com/thehairnarrative-com-journal/"
            "immutable-revisions/*/*/*/package.json",
            private_package,
        )
        self.assertNotIn(
            "thehairnarrative.com/thehairnarrative-com-journal/*",
            private_package,
        )
        self.assertNotIn("/working/", private_package)
        self.assertNotIn("/draft", private_package)
        self.assertIn("dynamodb:EnclosingOperation: TransactWriteItems", public_write)
        self.assertNotIn("HUB#zoosite-main", role)
        self.assertNotIn("s3:ListBucket", role)

    def test_public_media_is_read_only_and_cannot_invoke_internal_functions(self):
        role = _resource(_template(), "ThnContentHubV2PublicMediaRole")

        self.assertIn("dynamodb:GetItem", role)
        self.assertIn("s3:GetObjectVersion", role)
        for forbidden in (
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "dynamodb:DeleteItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "s3:PutObject",
            "s3:DeleteObject",
            "s3:ListBucket",
            "lambda:InvokeFunction",
        ):
            self.assertNotIn(forbidden, role)
        self.assertNotRegex(role, r"(?m)^\s+- s3:GetObject\s*$")

    def test_collectors_cannot_list_objects_or_derive_cross_scope_keys(self):
        template = _template()
        for role_id, module_name in (
            (
                "ThnContentHubV2PrivateAssetCollectorRole",
                "content_hub_v2_private_asset_gc.py",
            ),
            (
                "ThnContentHubV2PreparedOrphanCollectorRole",
                "prepared_orphan_collector_lambda.py",
            ),
        ):
            with self.subTest(role=role_id):
                role = _resource(template, role_id)
                source = (Path(__file__).resolve().parents[1] / module_name).read_text(
                    encoding="utf-8"
                )
                self.assertIn("s3:DeleteObject", role)
                self.assertNotIn("s3:ListBucket", role)
                self.assertNotIn("dynamodb:Scan", role)
                self.assertNotIn("HUB#zoosite-main", role)
                self.assertNotRegex(
                    source,
                    r"list_objects|list_object_versions|\.scan\(|glob\(|rglob\(",
                )

    def test_invalidation_can_update_only_its_outbox_and_cloudfront(self):
        role = _resource(_template(), "ThnContentHubV2InvalidationWorkerRole")

        self.assertIn("OUTBOX#test#thehairnarrative.com#", role)
        self.assertIn("cloudfront:CreateInvalidation", role)
        self.assertNotIn("ContentHubMetadataTable", role)
        self.assertNotIn("ContentHubPackagesBucket", role)
        self.assertNotIn("s3:", role)
        self.assertNotIn("dynamodb:PutItem", role)
        self.assertNotIn("dynamodb:DeleteItem", role)

    def test_emergency_withdraw_has_no_zoosite_private_or_storage_access(self):
        role = _resource(_template(), "ThnContentHubV2EmergencyWithdrawRole")

        self.assertIn("WithdrawExactThnProjection", role)
        self.assertNotIn("HUB#zoosite-main", role)
        self.assertNotIn("zoositioweb.com.mx", role)
        self.assertNotIn("zoolanding-auth-admin", role)
        self.assertNotIn("s3:", role)
        self.assertNotIn("dynamodb:Query", role)
        self.assertNotIn("dynamodb:Scan", role)

    def test_stateful_resources_are_test_only_retained_and_recoverable(self):
        template = _template()
        retained = set()
        for logical_id in STATEFUL_RESOURCES:
            resource = _resource(template, logical_id)
            retained.add(logical_id)
            self.assertIn("Condition: IsThnContentHubV2StateProvisioned", resource)
            self.assertIn("DeletionPolicy: Retain", resource)
            self.assertIn("UpdateReplacePolicy: Retain", resource)

        self.assertEqual(retained, STATEFUL_RESOURCES)
        for table_id in (
            "ThnContentHubV2MetadataTable",
            "ThnContentHubV2AuditTable",
        ):
            table = _resource(template, table_id)
            self.assertIn("DeletionProtectionEnabled: true", table)
            self.assertIn("PointInTimeRecoveryEnabled: true", table)
            self.assertIn("SSEEnabled: true", table)
            self.assertIn("zoolanding-content-hub-test-", table)

        bucket = _resource(template, "ThnContentHubV2PrivateStore")
        self.assertIn("zlp-thn-ch-test-private-", bucket)
        self.assertIn("Status: Enabled", bucket)
        self.assertIn("SSEAlgorithm: AES256", bucket)
        self.assertEqual(len(re.findall(r"BlockPublic\w+: true", bucket)), 2)
        self.assertIn("IgnorePublicAcls: true", bucket)
        self.assertIn("RestrictPublicBuckets: true", bucket)


if __name__ == "__main__":
    unittest.main()
