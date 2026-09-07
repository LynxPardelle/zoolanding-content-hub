import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = REPO_ROOT / "template.yaml"

FUNCTIONS = {
    "ThnContentHubV2AuthoringFunction": (
        "ThnContentHubV2AuthoringRole",
        "zlp-thn-ch-test-authoring",
        "lambda_function.thn_content_hub_v2_handler",
    ),
    "ThnContentHubV2PrivateAssetCollectorFunction": (
        "ThnContentHubV2PrivateAssetCollectorRole",
        "zlp-thn-ch-test-private-asset-gc",
        "content_hub_v2_private_asset_gc.lambda_handler",
    ),
    "ThnContentHubV2PublisherFunction": (
        "ThnContentHubV2PublisherRole",
        "zlp-thn-ch-test-publisher",
        "publisher_lambda.lambda_handler",
    ),
    "ThnContentHubV2PublicMediaFunction": (
        "ThnContentHubV2PublicMediaRole",
        "zlp-thn-ch-test-public-media",
        "public_media_lambda.lambda_handler",
    ),
    "ThnContentHubV2InvalidationWorkerFunction": (
        "ThnContentHubV2InvalidationWorkerRole",
        "zlp-thn-ch-test-invalidation",
        "invalidation_worker_lambda.lambda_handler",
    ),
    "ThnContentHubV2EmergencyWithdrawFunction": (
        "ThnContentHubV2EmergencyWithdrawRole",
        "zlp-thn-ch-test-emergency-withdraw",
        "emergency_withdraw_lambda.lambda_handler",
    ),
    "ThnContentHubV2PreparedOrphanCollectorFunction": (
        "ThnContentHubV2PreparedOrphanCollectorRole",
        "zlp-thn-ch-test-prepared-orphan-gc",
        "prepared_orphan_collector_lambda.lambda_handler",
    ),
}

STATEFUL_RESOURCES = {
    "ThnContentHubV2MetadataTable",
    "ThnContentHubV2AuditTable",
    "ThnContentHubV2PrivateStore",
}


def _template() -> str:
    return TEMPLATE_PATH.read_text(encoding="utf-8")


def _mapping_block(text: str, key: str, indent: int) -> str:
    lines = text.splitlines(keepends=True)
    marker = " " * indent + key + ":"
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if line.rstrip("\r\n").rstrip() == marker
        ),
        None,
    )
    if start is None:
        raise AssertionError(f"Missing YAML mapping: {key}")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index].rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        leading = len(line) - len(line.lstrip(" "))
        if leading <= indent:
            end = index
            break
    return "".join(lines[start:end])


def _resource(text: str, logical_id: str) -> str:
    return _mapping_block(_mapping_block(text, "Resources", 0), logical_id, 2)


def _parameter(text: str, name: str) -> str:
    return _mapping_block(_mapping_block(text, "Parameters", 0), name, 2)


def _statement(block: str, sid: str) -> str:
    match = re.search(rf"(?ms)- Sid: {re.escape(sid)}.*?(?=\n\s+- Sid:|\Z)", block)
    if match is None:
        raise AssertionError(f"Missing IAM statement: {sid}")
    return match.group(0)


class ThnContentHubV2Task019TemplateTests(unittest.TestCase):
    def test_declares_exactly_seven_separate_function_role_pairs(self):
        template = _template()
        resources = _mapping_block(template, "Resources", 0)
        function_ids = set(
            re.findall(r"(?m)^  (ThnContentHubV2[A-Za-z0-9]+Function):\s*$", resources)
        )
        role_ids = set(
            re.findall(r"(?m)^  (ThnContentHubV2[A-Za-z0-9]+Role):\s*$", resources)
        )

        self.assertEqual(function_ids, set(FUNCTIONS))
        self.assertEqual(role_ids, {definition[0] for definition in FUNCTIONS.values()})

        for function_id, (role_id, role_name, handler) in FUNCTIONS.items():
            with self.subTest(function=function_id):
                function = _resource(template, function_id)
                role = _resource(template, role_id)
                self.assertIn("Type: AWS::Serverless::Function", function)
                self.assertIn("Condition: IsThnContentHubV2Enabled", function)
                self.assertIn(f"Handler: {handler}", function)
                self.assertIn("AutoPublishAlias: test", function)
                self.assertRegex(
                    function,
                    rf"(?ms)Role:\s*\n\s+Fn::GetAtt:\s*\n\s+- {re.escape(role_id)}\s*\n\s+- Arn",
                )
                self.assertIn("Type: AWS::IAM::Role", role)
                self.assertIn("Condition: IsThnContentHubV2Enabled", role)
                self.assertIn(f"RoleName: {role_name}", role)
                self.assertLessEqual(len(role_name), 64)
                self.assertIn("Service: lambda.amazonaws.com", role)

    def test_every_reserved_v2_role_name_is_deployable(self):
        template = _template()
        role_names = set(
            re.findall(r"role/(zlp-thn-ch-test-[A-Za-z0-9+=,.@_-]+)", template)
        )
        role_names.update(definition[1] for definition in FUNCTIONS.values())
        self.assertEqual(
            role_names, {definition[1] for definition in FUNCTIONS.values()}
        )
        for role_name in role_names:
            self.assertLessEqual(len(role_name), 64)

        self.assertNotRegex(
            template,
            r"role/zoolanding-content-hub-test-ThnContentHubV2(?:PrivateAssetCollector|InvalidationWorker|PreparedOrphanCollector)Role",
        )

    def test_v2_physical_function_and_bucket_names_fit_aws_limits(self):
        template = _template()
        for function_id in FUNCTIONS:
            function = _resource(template, function_id)
            match = re.search(r"(?m)^      FunctionName: ([A-Za-z0-9-_]+)$", function)
            self.assertIsNotNone(match, function_id)
            self.assertLessEqual(len(match.group(1)), 64, function_id)

        bucket = _resource(template, "ThnContentHubV2PrivateStore")
        match = re.search(r"Fn::Sub: ([A-Za-z0-9${}_.:-]+)$", bucket, re.MULTILINE)
        self.assertIsNotNone(match)
        longest_resolved_name = (
            match.group(1)
            .replace("${AWS::AccountId}", "123456789012")
            .replace("${AWS::Region}", "ap-southeast-7")
        )
        self.assertLessEqual(len(longest_resolved_name), 63)

    def test_v2_roles_reject_broad_invalid_and_cross_scope_permissions(self):
        template = _template()
        for role_id, _, _ in FUNCTIONS.values():
            with self.subTest(role=role_id):
                role = _resource(template, role_id)
                self.assertNotRegex(role, r"(?m)^\s+Resource:\s+['\"]?\*['\"]?\s*$")
                self.assertNotIn("dynamodb:TransactWriteItems", role)
                self.assertNotIn("dynamodb:Scan", role)
                self.assertNotIn("s3:ListBucket", role)
                self.assertNotIn("HUB#zoosite-main", role)
                self.assertNotIn("#prod#", role)

    def test_v2_state_and_execution_are_independently_default_off_and_test_only(self):
        template = _template()
        enabled = _parameter(template, "EnableThnContentHubV2")
        provision = _parameter(template, "ProvisionThnContentHubV2State")
        gate = _parameter(template, "ThnContentHubV2TerminationProtectionGate")
        state_condition = _mapping_block(
            template, "IsThnContentHubV2StateProvisioned", 2
        )
        enabled_condition = _mapping_block(template, "IsThnContentHubV2Enabled", 2)
        rules = _mapping_block(template, "Rules", 0)

        self.assertIn("Default: 'false'", enabled)
        self.assertIn("Default: 'false'", provision)
        self.assertIn("Default: BLOCKED", gate)
        self.assertIn("CONFIRMED_ENABLED", gate)
        self.assertIn("ThnContentHubV2StateProvisioningRule:", rules)
        self.assertIn("ThnContentHubV2ActivationRule:", rules)
        self.assertIn("Ref: EnvironmentName", state_condition)
        self.assertIn("Ref: ProvisionThnContentHubV2State", state_condition)
        self.assertNotIn("EnableThnContentHubV2", state_condition)
        for parameter in (
            "EnvironmentName",
            "ProvisionThnContentHubV2State",
            "EnableThnContentHubV2",
            "ThnContentHubV2TerminationProtectionGate",
        ):
            self.assertIn(f"Ref: {parameter}", enabled_condition)

        metadata = _mapping_block(template, "Metadata", 0)
        guard = _mapping_block(metadata, "ThnContentHubV2DeploymentGuards", 2)
        self.assertIn("GateParameter: ThnContentHubV2TerminationProtectionGate", guard)
        self.assertIn("FailureMode: BLOCK", guard)
        self.assertIn("DefaultState: BLOCKED", guard)
        self.assertNotIn("EnableTerminationProtection:", template)

    def test_declares_only_the_three_dedicated_retained_private_stores(self):
        template = _template()
        resources = _mapping_block(template, "Resources", 0)
        stateful_ids = set()
        for logical_id in re.findall(
            r"(?m)^  (ThnContentHubV2[A-Za-z0-9]+):\s*$", resources
        ):
            block = _resource(template, logical_id)
            if "DeletionPolicy: Retain" in block:
                stateful_ids.add(logical_id)
                self.assertIn("Condition: IsThnContentHubV2StateProvisioned", block)
                self.assertNotIn("Condition: IsThnContentHubV2Enabled", block)
                self.assertIn("UpdateReplacePolicy: Retain", block)
        self.assertEqual(stateful_ids, STATEFUL_RESOURCES)

        for logical_id, table_name in (
            (
                "ThnContentHubV2MetadataTable",
                "zoolanding-content-hub-test-ThnContentHubV2Metadata",
            ),
            (
                "ThnContentHubV2AuditTable",
                "zoolanding-content-hub-test-ThnContentHubV2Audit",
            ),
        ):
            table = _resource(template, logical_id)
            self.assertIn("Type: AWS::DynamoDB::Table", table)
            self.assertIn(f"TableName: {table_name}", table)
            self.assertIn("BillingMode: PAY_PER_REQUEST", table)
            self.assertIn("DeletionProtectionEnabled: true", table)
            self.assertIn("PointInTimeRecoveryEnabled: true", table)
            self.assertIn("SSEEnabled: true", table)

        bucket = _resource(template, "ThnContentHubV2PrivateStore")
        self.assertIn("Type: AWS::S3::Bucket", bucket)
        self.assertIn(
            "Fn::Sub: zlp-thn-ch-test-private-${AWS::AccountId}-${AWS::Region}",
            bucket,
        )
        self.assertIn("Status: Enabled", bucket)
        for setting in (
            "BlockPublicAcls",
            "BlockPublicPolicy",
            "IgnorePublicAcls",
            "RestrictPublicBuckets",
        ):
            self.assertIn(f"{setting}: true", bucket)
        self.assertIn("SSEAlgorithm: AES256", bucket)

    def test_authoring_and_public_media_own_only_the_closed_routes(self):
        template = _template()
        authoring = _resource(template, "ThnContentHubV2AuthoringFunction")
        public_media = _resource(template, "ThnContentHubV2PublicMediaFunction")
        authoring_routes = set(
            re.findall(
                r"(?ms)Method: ([A-Z]+)\s+Path: (/features/content-hub-v2/[^\s]+)",
                authoring,
            )
        )
        self.assertEqual(
            authoring_routes,
            {
                ("POST", "/features/content-hub-v2/read"),
                ("POST", "/features/content-hub-v2/action"),
            },
        )
        self.assertIn("Method: GET", public_media)
        self.assertIn(
            "Path: /features/content-hub-v2/public-media/{articleId}/{locale}/{revisionId}/{assetId}/{variantId}",
            public_media,
        )

        for function_id in set(FUNCTIONS) - {
            "ThnContentHubV2AuthoringFunction",
            "ThnContentHubV2PublicMediaFunction",
        }:
            self.assertNotIn("Type: HttpApi", _resource(template, function_id))

    def test_worker_and_collector_events_are_exact_and_dormant(self):
        template = _template()
        schedules = {
            "ThnContentHubV2PrivateAssetCollectorFunction": "rate(1 day)",
            "ThnContentHubV2InvalidationWorkerFunction": "rate(1 minute)",
            "ThnContentHubV2PreparedOrphanCollectorFunction": "rate(1 day)",
        }
        for logical_id, schedule in schedules.items():
            with self.subTest(function=logical_id):
                block = _resource(template, logical_id)
                self.assertIn("Type: Schedule", block)
                self.assertIn(f"Schedule: {schedule}", block)
                self.assertIn("Enabled: false", block)
        for logical_id in (
            "ThnContentHubV2PublisherFunction",
            "ThnContentHubV2EmergencyWithdrawFunction",
        ):
            self.assertNotIn("Events:", _resource(template, logical_id))

    def test_authoring_can_only_read_auth_and_mutate_private_scope(self):
        template = _template()
        role = _resource(template, "ThnContentHubV2AuthoringRole")
        auth_read = _statement(role, "ReadExactThnAuthState")
        private_state = _statement(role, "MutateExactThnPrivateState")
        private_store = _statement(role, "ReadWriteExactThnPrivateObjects")

        self.assertIn("dynamodb:GetItem", auth_read)
        self.assertIn("zoolanding-auth-admin-test-ThnSessionV2", auth_read)
        self.assertIn("zoolanding-auth-admin-test-ThnCurrentUserStateV2", auth_read)
        for forbidden in ("PutItem", "UpdateItem", "DeleteItem", "Query", "Scan"):
            self.assertNotIn(f"dynamodb:{forbidden}", auth_read)

        self.assertIn("ThnContentHubV2MetadataTable", private_state)
        self.assertIn(
            "THN#test#thehairnarrative.com#journal-owner#thehairnarrative-com#thehairnarrative-com-journal#*",
            private_state,
        )
        self.assertNotIn("ContentHubMetadataTable", private_state)
        self.assertNotIn("ContentHubPackagesBucket", private_store)
        self.assertNotIn("dynamodb:Scan", role)
        self.assertNotIn("s3:ListBucket", role)

    def test_role_boundaries_keep_public_projection_and_collection_separate(self):
        template = _template()
        publisher = _resource(template, "ThnContentHubV2PublisherRole")
        public_media = _resource(template, "ThnContentHubV2PublicMediaRole")
        private_gc = _resource(template, "ThnContentHubV2PrivateAssetCollectorRole")
        prepared_gc = _resource(template, "ThnContentHubV2PreparedOrphanCollectorRole")
        invalidation = _resource(template, "ThnContentHubV2InvalidationWorkerRole")

        self.assertIn("FinalizeExactThnProjection", publisher)
        self.assertIn("HUB#thehairnarrative-com-journal", publisher)
        self.assertIn("SLUG#test#thehairnarrative.com#en", publisher)
        self.assertIn("SLUG#test#thehairnarrative.com#es", publisher)
        self.assertNotIn("zoolanding-auth-admin-test-ThnSessionV2", publisher)

        self.assertIn("dynamodb:GetItem", public_media)
        self.assertIn("s3:GetObjectVersion", public_media)
        for forbidden in ("PutItem", "UpdateItem", "DeleteItem", "Query", "Scan"):
            self.assertNotIn(f"dynamodb:{forbidden}", public_media)
        for forbidden in ("s3:PutObject", "s3:DeleteObject", "s3:ListBucket"):
            self.assertNotIn(forbidden, public_media)

        for collector in (private_gc, prepared_gc):
            self.assertIn("s3:DeleteObject", collector)
            self.assertNotIn("s3:ListBucket", collector)
            self.assertNotIn("dynamodb:Scan", collector)
        self.assertIn("cloudfront:CreateInvalidation", invalidation)
        self.assertNotIn("s3:", invalidation)

    def test_emergency_withdraw_has_only_named_operator_invocation(self):
        template = _template()
        function = _resource(template, "ThnContentHubV2EmergencyWithdrawFunction")
        role = _resource(template, "ThnContentHubV2EmergencyWithdrawRole")
        invoke_policy = _resource(
            template, "ThnContentHubV2EmergencyWithdrawInvokePolicy"
        )
        permission = _resource(
            template, "ThnContentHubV2EmergencyWithdrawInvokePermission"
        )

        self.assertNotIn("Events:", function)
        self.assertIn("WithdrawExactThnProjection", role)
        self.assertNotIn("HUB#zoosite-main", role)
        self.assertIn("lambda:InvokeFunction", invoke_policy)
        self.assertIn("zoolanding-thn-content-hub-test-operator", invoke_policy)
        self.assertIn("ThnContentHubV2EmergencyWithdrawFunction.Alias", invoke_policy)
        self.assertIn("AWS::Lambda::Permission", permission)
        self.assertIn("lambda:InvokeFunction", permission)
        self.assertIn("Ref: ThnContentHubV2EmergencyOperatorRoleArn", permission)
        self.assertIn("ThnContentHubV2EmergencyWithdrawFunction.Alias", permission)
        self.assertNotIn("AWS::Lambda::ResourcePolicy", template)

    def test_legacy_v1_resources_do_not_inherit_v2_state_or_roles(self):
        template = _template()
        legacy_function = _resource(template, "ContentHubFunction")
        legacy_role = _resource(template, "ContentHubFunctionRole")
        self.assertNotIn("ThnContentHubV2", legacy_function)
        self.assertNotIn("content-hub-v2", legacy_function)
        self.assertNotIn("ThnContentHubV2", legacy_role)
        self.assertIn("Path: /features/content-hub/read", legacy_function)
        self.assertIn("Path: /features/content-hub/action", legacy_function)


if __name__ == "__main__":
    unittest.main()
