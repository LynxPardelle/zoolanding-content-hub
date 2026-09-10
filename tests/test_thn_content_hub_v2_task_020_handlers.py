import importlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]

V2_HANDLERS = {
    "ThnContentHubV2AuthoringFunction": (
        "lambda_function",
        "thn_content_hub_v2_handler",
    ),
    "ThnContentHubV2PrivateAssetCollectorFunction": (
        "content_hub_v2_private_asset_gc",
        "lambda_handler",
    ),
    "ThnContentHubV2PublisherFunction": ("publisher_lambda", "lambda_handler"),
    "ThnContentHubV2PublicMediaFunction": ("public_media_lambda", "lambda_handler"),
    "ThnContentHubV2InvalidationWorkerFunction": (
        "invalidation_worker_lambda",
        "lambda_handler",
    ),
    "ThnContentHubV2EmergencyWithdrawFunction": (
        "emergency_withdraw_lambda",
        "lambda_handler",
    ),
    "ThnContentHubV2PreparedOrphanCollectorFunction": (
        "prepared_orphan_collector_lambda",
        "lambda_handler",
    ),
}

ALL_ARTIFACTS = {
    "ServiceBindingRegistryV2MutationFunction": {
        "service_binding_registry_operator_lambda.py",
        "service_binding_registry_v2.py",
    },
    "ThnContentHubV2AuthoringFunction": {
        "lambda_function.py",
        "content_hub_v2_authoring_handler.py",
        "content_hub_v2_actor_fence.py",
        "content_hub_v2_editor_model.py",
        "content_hub_v2_editor_service.py",
        "content_hub_v2_editor_store.py",
        "content_hub_v2_state_keys.py",
        "content_hub_v2_publication_contract.py",
        "content_hub_v2_publication_gateway.py",
        "content_hub_v2_private_upload.py",
        "content_hub_v2_media_store.py",
        "content_hub_v2_authorization.py",
        "content_hub_v2_registry_fence.py",
        "service_binding_registry_consumer_v2.py",
        "service_binding_registry_operator_lambda.py",
        "service_binding_registry_v2.py",
    },
    "ThnContentHubV2PrivateAssetCollectorFunction": {
        "content_hub_v2_private_asset_gc.py",
        "content_hub_v2_registry_fence.py",
        "service_binding_registry_consumer_v2.py",
        "service_binding_registry_operator_lambda.py",
        "service_binding_registry_v2.py",
    },
    "ThnContentHubV2PublisherFunction": {
        "publisher_lambda.py",
        "content_hub_v2_publication_contract.py",
        "content_hub_v2_finalization.py",
        "content_hub_v2_manifest_update.py",
        "content_hub_v2_projection_manifest.py",
        "content_hub_v2_projection_delta.py",
        "content_hub_v2_projection.py",
        "content_hub_v2_projection_store.py",
        "content_hub_v2_preparation.py",
        "content_hub_v2_state_keys.py",
        "content_hub_v2_editor_model.py",
        "content_hub_v2_authorization.py",
        "content_hub_v2_actor_fence.py",
        "content_hub_v2_registry_fence.py",
        "service_binding_registry_consumer_v2.py",
        "service_binding_registry_operator_lambda.py",
        "service_binding_registry_v2.py",
    },
    "ThnContentHubV2PublicMediaFunction": {"public_media_lambda.py"},
    "ThnContentHubV2InvalidationWorkerFunction": {
        "invalidation_worker_lambda.py",
        "service_binding_registry_consumer_v2.py",
        "service_binding_registry_operator_lambda.py",
        "service_binding_registry_v2.py",
    },
    "ThnContentHubV2EmergencyWithdrawFunction": {
        "emergency_withdraw_lambda.py",
        "content_hub_v2_projection_manifest.py",
        "service_binding_registry_consumer_v2.py",
        "service_binding_registry_operator_lambda.py",
        "service_binding_registry_v2.py",
    },
    "ThnContentHubV2PreparedOrphanCollectorFunction": {
        "prepared_orphan_collector_lambda.py",
        "content_hub_v2_projection_store.py",
        "content_hub_v2_projection.py",
        "content_hub_v2_preparation.py",
        "content_hub_v2_editor_model.py",
        "content_hub_v2_authorization.py",
        "content_hub_v2_actor_fence.py",
        "content_hub_v2_registry_fence.py",
        "content_hub_v2_state_keys.py",
        "content_hub_v2_projection_manifest.py",
        "service_binding_registry_consumer_v2.py",
        "service_binding_registry_operator_lambda.py",
        "service_binding_registry_v2.py",
    },
    "ContentHubFunction": {"lambda_function.py"},
}


def _resource(template: str, logical_id: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(logical_id)}:\s*$.*?(?=^  [A-Za-z0-9]+:\s*$|\Z)",
        template,
    )
    if match is None:
        raise AssertionError(f"Missing resource: {logical_id}")
    return match.group(0)


class ThnContentHubV2Task020HandlerTests(unittest.TestCase):
    def test_exact_v2_handler_files_and_entrypoints_exist(self):
        template = (PROJECT_ROOT / "template.yaml").read_text(encoding="utf-8")
        for logical_id, (module_name, function_name) in V2_HANDLERS.items():
            with self.subTest(function=logical_id):
                module = importlib.import_module(module_name)
                self.assertTrue(callable(getattr(module, function_name, None)))
                function = _resource(template, logical_id)
                self.assertIn(f"Handler: {module_name}.{function_name}", function)

    def test_authoring_entrypoint_fails_closed_without_entering_v1_dispatch(self):
        module = importlib.import_module("lambda_function")
        event = {
            "rawPath": "/features/content-hub-v2/read",
            "requestContext": {"requestId": "task-020", "http": {"method": "POST"}},
            "body": json.dumps({"input": {"contentHub": {"read": "revisionList"}}}),
        }
        with (
            mock.patch.object(module, "_read_response") as legacy_read,
            mock.patch.object(module, "_action_response") as legacy_action,
            mock.patch.object(module, "_dynamodb_resource") as dynamodb,
            mock.patch.object(module, "_s3_client") as s3,
        ):
            response = module.thn_content_hub_v2_handler(event, object())

        self.assertEqual(response["statusCode"], 400)
        body = json.loads(response["body"])
        self.assertEqual(body["code"], "unsupported_operation")
        self.assertEqual(body["message"], "Unsupported content hub operation")
        self.assertEqual(response["headers"]["cache-control"], "no-store")
        legacy_read.assert_not_called()
        legacy_action.assert_not_called()
        dynamodb.assert_not_called()
        s3.assert_not_called()

    def test_non_authoring_handlers_are_distinct_and_fail_closed_before_io(self):
        internal_modules = {
            "content_hub_v2_private_asset_gc",
            "publisher_lambda",
            "invalidation_worker_lambda",
            "prepared_orphan_collector_lambda",
        }
        for module_name in internal_modules:
            with self.subTest(module=module_name):
                module = importlib.import_module(module_name)
                with self.assertRaises(module.HandlerNotActiveError):
                    module.lambda_handler({"unexpected": "input"}, object())
                source = (PROJECT_ROOT / f"{module_name}.py").read_text(
                    encoding="utf-8"
                )
                with mock.patch("boto3.client") as client, self.assertRaises(module.HandlerNotActiveError):
                    module.lambda_handler({"unexpected": "input"}, object())
                client.assert_not_called()
                for other_module in internal_modules - {module_name}:
                    self.assertNotIn(f"import {other_module}", source)

        emergency = importlib.import_module("emergency_withdraw_lambda")
        with (
            mock.patch.object(
                emergency.AwsEmergencyWithdrawalRuntime,
                "from_environment",
            ) as runtime,
            self.assertRaises(emergency.EmergencyWithdrawalError),
        ):
            emergency.lambda_handler({"unexpected": "input"}, object())
        runtime.assert_not_called()

        public_media = importlib.import_module("public_media_lambda")
        response = public_media.lambda_handler({"unexpected": "input"}, object())
        self.assertEqual(response["statusCode"], 404)
        self.assertEqual(
            json.loads(response["body"]), {"ok": False, "code": "not_found"}
        )
        self.assertEqual(response["headers"]["cache-control"], "no-store")

    def test_every_lambda_uses_an_exact_makefile_artifact(self):
        template = (PROJECT_ROOT / "template.yaml").read_text(encoding="utf-8")
        self.assertEqual(
            template.count("Type: AWS::Serverless::Function"), len(ALL_ARTIFACTS)
        )
        self.assertEqual(template.count("BuildMethod: makefile"), len(ALL_ARTIFACTS))
        makefile = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")
        for logical_id in ALL_ARTIFACTS:
            with self.subTest(function=logical_id):
                self.assertIn("BuildMethod: makefile", _resource(template, logical_id))
                self.assertIn(f"build-{logical_id}:", makefile)
                self.assertIn(
                    f'build_lambda_artifact.py {logical_id} "$(ARTIFACTS_DIR)"',
                    makefile,
                )

    def test_builder_copies_only_each_runtime_source_allowlist(self):
        from tools import build_lambda_artifact as builder
        from tools import check_lambda_artifacts as checker

        self.assertEqual(
            {target: set(files) for target, files in builder.SOURCE_ALLOWLIST.items()},
            ALL_ARTIFACTS,
        )
        for target, expected in ALL_ARTIFACTS.items():
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as directory,
            ):
                destination = pathlib.Path(directory)
                builder.build_artifact(target, destination, install_dependencies=False)
                actual = {
                    path.relative_to(destination).as_posix()
                    for path in destination.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(actual, expected)
                checker.validate_artifact(target, destination)

    def test_each_source_only_artifact_imports_its_declared_entrypoint(self):
        from tools import build_lambda_artifact as builder

        entrypoints = {
            "ServiceBindingRegistryV2MutationFunction": (
                "service_binding_registry_operator_lambda",
                "lambda_handler",
            ),
            **V2_HANDLERS,
            "ContentHubFunction": ("lambda_function", "lambda_handler"),
        }
        environment = dict(os.environ)
        environment.pop("PYTHONPATH", None)
        for target, (module_name, function_name) in entrypoints.items():
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as directory,
            ):
                destination = pathlib.Path(directory)
                builder.build_artifact(target, destination, install_dependencies=False)
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        (
                            f"import {module_name} as module; "
                            f"assert callable(module.{function_name})"
                        ),
                    ],
                    cwd=destination,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_only_boto3_consumers_install_runtime_requirements(self):
        from tools import build_lambda_artifact as builder

        expected = {
            "ThnContentHubV2InvalidationWorkerFunction",
            "ThnContentHubV2PreparedOrphanCollectorFunction",
            "ServiceBindingRegistryV2MutationFunction",
            "ThnContentHubV2AuthoringFunction",
            "ThnContentHubV2PublisherFunction",
            "ThnContentHubV2PrivateAssetCollectorFunction",
            "ThnContentHubV2PublicMediaFunction",
            "ThnContentHubV2EmergencyWithdrawFunction",
            "ContentHubFunction",
        }
        self.assertEqual(set(builder.RUNTIME_REQUIREMENTS), expected)
        for target in ALL_ARTIFACTS:
            with (
                self.subTest(target=target),
                tempfile.TemporaryDirectory() as directory,
                mock.patch.object(builder.subprocess, "run") as run,
            ):
                destination = pathlib.Path(directory)
                builder.build_artifact(target, destination)
                if target in expected:
                    run.assert_called_once()
                    command = run.call_args.args[0]
                    self.assertIn(str(PROJECT_ROOT / "requirements.txt"), command)
                    self.assertEqual(
                        command[-2:], ["--target", str(destination.resolve())]
                    )
                    self.assertTrue(run.call_args.kwargs["check"])
                else:
                    run.assert_not_called()

    def test_builder_and_checker_reject_unknown_dirty_or_cross_function_artifacts(self):
        from tools import build_lambda_artifact as builder
        from tools import check_lambda_artifacts as checker

        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaises(builder.ArtifactBuildError),
        ):
            builder.build_artifact(
                "UnknownFunction",
                pathlib.Path(directory),
                install_dependencies=False,
            )

        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory)
            builder.build_artifact(
                "ThnContentHubV2PublisherFunction",
                destination,
                install_dependencies=False,
            )
            (destination / "lambda_function.py").write_text(
                "forbidden", encoding="utf-8"
            )
            with self.assertRaises(checker.ArtifactValidationError):
                checker.validate_artifact(
                    "ThnContentHubV2PublisherFunction", destination
                )

        with tempfile.TemporaryDirectory() as directory:
            destination = pathlib.Path(directory)
            (destination / "already-present.txt").write_text("dirty", encoding="utf-8")
            with self.assertRaises(builder.ArtifactBuildError):
                builder.build_artifact(
                    "ThnContentHubV2PublisherFunction",
                    destination,
                    install_dependencies=False,
                )


if __name__ == "__main__":
    unittest.main()
