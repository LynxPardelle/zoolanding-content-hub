#!/usr/bin/env python3
"""Isolated, retained-state THN Content Hub TEST release boundary.

Shared v1 resources and parameter values are preserved from the deployed stack.
This is deliberately separate from the ordinary, v2-disabled deploy path.
"""

from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
import subprocess
import tempfile
import time
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tools.prepare_test_parameters import _thn_defaults, _thn_parameters
from tools import thn_api_boundary
KEYS = frozenset(_thn_defaults()) - {"ServiceBindingRegistryOperatorRoleArn"}
from tools.prepare_test_parameters import ParameterPreparationError
from tools import review_test_change_set as ordinary_review

STACK = "zoolanding-content-hub-test"
REGION = "us-east-1"
ACCOUNT_HASH = "3e19eeb25ac142d015c5a4d347dc58784b0a79a124f1353b5e92d90673810a8f"
PREFIX = "ThnContentHubV2"
ENABLE = "EnableThnContentHubV2"
STATE = "ProvisionThnContentHubV2State"
GATE = "ThnContentHubV2TerminationProtectionGate"
OPERATIONS = frozenset({"provision", "enable", "disable"})
REGISTRY_TABLE = "zoolanding-content-hub-test-ServiceBindingRegistryV2"
SCOPE = {"environment": "test", "domain": "thehairnarrative.com", "serviceBindingId": "thn-journal-test-v2",
         "hubId": "thehairnarrative-com-journal", "tenantId": "thehairnarrative-com", "authProfileId": "journal-owner"}
STATE_TYPES = frozenset({"AWS::DynamoDB::Table", "AWS::S3::Bucket"})
PERSISTENT_RUNTIME_TYPES = frozenset({"AWS::Lambda::Function", "AWS::Lambda::Alias", "AWS::IAM::Role", "AWS::Events::Rule"})
REMOVABLE_TYPES = frozenset({"AWS::Lambda::Permission", "AWS::IAM::Policy"})
PAIRS = ("Authoring", "PrivateAssetCollector", "Publisher", "PublicMedia", "InvalidationWorker", "EmergencyWithdraw", "PreparedOrphanCollector")
RESOURCE_TYPES = {
    **{"ThnContentHubV2" + pair + suffix: kind for pair in PAIRS
       for suffix, kind in (("Function", "AWS::Serverless::Function"), ("Role", "AWS::IAM::Role"))},
    "ThnContentHubV2MetadataTable": "AWS::DynamoDB::Table",
    "ThnContentHubV2AuditTable": "AWS::DynamoDB::Table",
    "ThnContentHubV2PrivateStore": "AWS::S3::Bucket",
    "ThnContentHubV2AuthoringFunctionReadPermission": "AWS::Lambda::Permission",
    "ThnContentHubV2AuthoringFunctionActionPermission": "AWS::Lambda::Permission",
    "ThnContentHubV2PublicMediaFunctionPublicMediaPermission": "AWS::Lambda::Permission",
    "ThnContentHubV2EmergencyWithdrawInvokePermission": "AWS::Lambda::Permission",
    "ThnContentHubV2EmergencyWithdrawInvokePolicy": "AWS::IAM::Policy",
}
SCHEDULES = {"ThnContentHubV2" + pair + "Function" + event for pair, event in (
    ("PrivateAssetCollector", "CollectionSchedule"), ("InvalidationWorker", "InvalidationSchedule"), ("PreparedOrphanCollector", "CollectionSchedule"))}


def _allowed_resource(logical, kind):
    expected = RESOURCE_TYPES.get(logical)
    if expected:
        return kind == ("AWS::Lambda::Function" if expected == "AWS::Serverless::Function" else expected)
    if logical in SCHEDULES:
        return kind == "AWS::Events::Rule"
    if logical in {key + "Permission" for key in SCHEDULES}:
        return kind == "AWS::Lambda::Permission"
    for pair in PAIRS:
        function = "ThnContentHubV2" + pair + "Function"
        if logical == function + "Aliastest":
            return kind == "AWS::Lambda::Alias"
        if isinstance(logical, str) and re.fullmatch(function + r"Version[a-f0-9]{10}", logical):
            return kind == "AWS::Lambda::Version"
    return False



class ReleaseBlocked(RuntimeError):
    """A sanitized release-boundary failure; never includes provider inputs."""


def validate_deploy_identity(identity: Any) -> None:
    """Pin the actual STS principal, never a supplied role/context field."""
    account = identity.get("Account") if isinstance(identity, dict) else None
    if (not isinstance(account, str) or re.fullmatch(r"[0-9]{12}", account) is None
            or not hmac.compare_digest(hashlib.sha256(account.encode("ascii")).hexdigest(), ACCOUNT_HASH)
            or re.fullmatch(rf"arn:aws:sts::{account}:assumed-role/zoolanding-content-hub-test-deploy/[A-Za-z0-9+=,.@_-]{{2,64}}",
                            str(identity.get("Arn", ""))) is None):
        raise ReleaseBlocked("test_deployment_principal_mismatch")


def _parameters(stack: dict) -> dict[str, str]:
    result = {}
    items = stack.get("Parameters")
    if not isinstance(items, list):
        raise ReleaseBlocked("stack_parameters_invalid")
    for item in items:
        if (not isinstance(item, dict) or not isinstance(item.get("ParameterKey"), str)
                or not isinstance(item.get("ParameterValue"), str) or item["ParameterKey"] in result):
            raise ReleaseBlocked("stack_parameters_invalid")
        result[item["ParameterKey"]] = item["ParameterValue"]
    return result


def validate_stack(stack: Any, account: str, *, expected_account_hash: str = ACCOUNT_HASH) -> None:
    if (not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account)
            or expected_account_hash == "0" * 64
            or not hmac.compare_digest(hashlib.sha256(account.encode("ascii")).hexdigest(), expected_account_hash)):
        raise ReleaseBlocked("test_account_mismatch")
    expected_arn = rf"arn:aws:cloudformation:{REGION}:{account}:stack/{STACK}/[A-Za-z0-9-]+"
    if (not isinstance(stack, dict) or stack.get("StackName") != STACK
            or re.fullmatch(expected_arn, str(stack.get("StackId", ""))) is None
            or stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}
            or stack.get("EnableTerminationProtection") is not True):
        raise ReleaseBlocked("test_stack_preflight_failed")
    if "RoleARN" in stack:
        raise ReleaseBlocked("hub_execution_role_must_remain_absent")
    if _parameters(stack).get("EnvironmentName") != "test":
        raise ReleaseBlocked("test_environment_mismatch")


def lifecycle_parameters(stack: dict, operation: str, raw_selection: str | None) -> list[dict]:
    previous = _parameters(stack)
    if operation not in OPERATIONS or previous.get("EnvironmentName") != "test":
        raise ReleaseBlocked("operation_invalid")
    if operation in {"enable", "disable"} and previous.get(STATE) != "true":
        raise ReleaseBlocked("retained_state_required")
    if operation == "provision" and previous.get(ENABLE, "false") != "false":
        raise ReleaseBlocked("provision_cannot_disable_runtime")
    values = {ENABLE: "false", STATE: "true", GATE: "CONFIRMED_ENABLED"}
    if operation == "enable":
        try:
            values = _thn_parameters({"THN_V2_TEST_PARAMETERS_JSON": raw_selection or "",
                "AWS_ROLE_ARN": f"arn:aws:iam::{str(stack.get('StackId', '')).split(':')[4]}:role/test-release"})
        except ParameterPreparationError:
            raise ReleaseBlocked("thn_test_selection_invalid") from None
        if values.pop("ServiceBindingRegistryOperatorRoleArn") != previous.get("ServiceBindingRegistryOperatorRoleArn"):
            raise ReleaseBlocked("shared_registry_operator_must_be_preprovisioned")
        if values[ENABLE] != "true" or values[STATE] != "true":
            raise ReleaseBlocked("enable_selection_required")
    result = [{"ParameterKey": key, "UsePreviousValue": True}
              for key in sorted(previous) if key not in values]
    result.extend({"ParameterKey": key, "ParameterValue": value} for key, value in sorted(values.items()))
    return result


def effective_parameters(template: dict, previous: dict, parameters: list[dict]) -> dict:
    """Resolve expected readback in memory; never turn masked secrets into writes."""
    declared = template.get("Parameters", {})
    overrides = {item["ParameterKey"]: item for item in parameters}
    if len(overrides) != len(parameters) or not set(overrides).issubset(declared):
        raise ReleaseBlocked("parameter_override_not_declared")
    result = {}
    for key, declaration in declared.items():
        supplied = overrides.get(key, {})
        if "ParameterValue" in supplied:
            value = supplied["ParameterValue"]
        elif supplied.get("UsePreviousValue") is True:
            value = previous.get(key)
        else:
            value = declaration.get("Default")
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            raise ReleaseBlocked("required_parameter_value_missing")
        result[key] = str(value)
    return result


def _thn_key(section: str, key: str) -> bool:
    if section == "Parameters":
        return key in KEYS
    if section == "Conditions":
        return key.startswith("Is" + PREFIX)
    if section == "Resources":
        return key in RESOURCE_TYPES
    return key.startswith(PREFIX)


def compose_template(candidate: dict, previous: dict, operation: str = "enable", live_processed: dict | None = None) -> dict:
    """Keep v1 byte-equivalent while installing only reviewed, prefixed v2 entries."""
    if operation not in OPERATIONS or not isinstance(candidate, dict) or not isinstance(previous, dict):
        raise ReleaseBlocked("template_invalid")
    if live_processed is None:
        raise ReleaseBlocked("verified_live_processed_template_required")
    if operation == "disable":
        for pair in PAIRS:
            for suffix in ("Function", "Role"):
                if previous.get("Resources", {}).get(PREFIX + pair + suffix, {}).get("Condition") != "IsThnContentHubV2StateProvisioned":
                    raise ReleaseBlocked("retained_runtime_migration_required")
        return deepcopy(previous)
    for key in ("Transform", "Globals", "Mappings"):
        if candidate.get(key) != previous.get(key):
            raise ReleaseBlocked("shared_template_drift")
    result = deepcopy(previous)
    try:
        new_api = deepcopy(candidate["Resources"]["ContentHubApi"])
        old_api = deepcopy(previous["Resources"]["ContentHubApi"])
        new_api["Properties"].pop("DefinitionBody", None)
        old_api["Properties"].pop("DefinitionBody", None)
        if new_api != old_api:
            raise ReleaseBlocked("shared_api_nonbody_source_drift")
        body = thn_api_boundary.compose_body(candidate, live_processed)
    except (KeyError, TypeError, thn_api_boundary.ApiBoundaryError):
        raise ReleaseBlocked("shared_api_composition_failed") from None
    for section in ("Resources", "Parameters", "Conditions", "Rules", "Outputs", "Metadata"):
        supplied = candidate.get(section, {})
        current = previous.get(section, {})
        if not isinstance(supplied, dict) or not isinstance(current, dict):
            raise ReleaseBlocked("template_invalid")
        if section == "Resources":
            if any(key.startswith("Thn") and key not in RESOURCE_TYPES for key in supplied):
                raise ReleaseBlocked("resource_not_allowlisted")
            if not set(RESOURCE_TYPES).issubset(supplied):
                raise ReleaseBlocked("required_thn_resource_missing")
            for key, kind in RESOURCE_TYPES.items():
                if supplied[key].get("Type") != kind:
                    raise ReleaseBlocked("resource_type_not_allowlisted")
                if kind in {"AWS::Serverless::Function", "AWS::IAM::Role"} and supplied[key].get("Condition") != "IsThnContentHubV2StateProvisioned":
                    raise ReleaseBlocked("runtime_retention_required")
        # A retained resource cannot disappear even from the source template.
        for key, value in current.items():
            if (section == "Resources" and _thn_key(section, key)
                    and value.get("Type") in STATE_TYPES and key not in supplied):
                raise ReleaseBlocked("retained_resource_missing")
        combined = {key: deepcopy(value) for key, value in current.items() if not _thn_key(section, key)}
        for key, value in supplied.items():
            if not _thn_key(section, key):
                continue
            if section == "Resources" and value.get("Type") in STATE_TYPES:
                if (value.get("DeletionPolicy") != "Retain" or value.get("UpdateReplacePolicy") != "Retain"
                        or value.get("Condition") != "IsThnContentHubV2StateProvisioned"):
                    raise ReleaseBlocked("state_retention_required")
            combined[key] = deepcopy(value)
        if combined:
            result[section] = combined
    result["Resources"]["ContentHubApi"]["Properties"]["DefinitionBody"] = body
    return result


def review_resources(changes: Any, operation: str, live_processed=None, candidate_processed=None, inventory=None) -> None:
    if operation not in OPERATIONS or not isinstance(changes, list):
        raise ReleaseBlocked("change_set_invalid")
    for change in changes:
        resource = change.get("ResourceChange", {}) if isinstance(change, dict) else {}
        if isinstance(resource, dict) and resource.get("LogicalResourceId") == "ContentHubApi":
            try:
                thn_api_boundary.review_shared_api(resource, live_processed, candidate_processed, inventory)
            except thn_api_boundary.ApiBoundaryError:
                raise ReleaseBlocked("shared_api_review_failed") from None
            continue
        if (not isinstance(change, dict) or change.get("Type") != "Resource" or not isinstance(resource, dict)
                or not _allowed_resource(resource.get("LogicalResourceId"), resource.get("ResourceType"))
                or resource.get("Replacement") not in (None, "False")):
            raise ReleaseBlocked("non_thn_or_replacement_change_forbidden")
        action = resource.get("Action")
        if resource.get("ResourceType") not in STATE_TYPES | PERSISTENT_RUNTIME_TYPES | REMOVABLE_TYPES | {"AWS::Lambda::Version"}:
            raise ReleaseBlocked("resource_type_not_allowlisted")
        if action in {"Add", "Modify"}:
            continue
        if (action == "Remove" and resource.get("ResourceType") == "AWS::Lambda::Version"
                and resource.get("PolicyAction") == "Retain"):
            continue
        if (action == "Remove" and operation == "disable"
                and resource.get("LogicalResourceId") in {key for key, kind in RESOURCE_TYPES.items() if kind in REMOVABLE_TYPES}):
            continue
        raise ReleaseBlocked("resource_removal_forbidden")


def validate_context(env: dict) -> None:
    if (env.get("GITHUB_REPOSITORY") != "LynxPardelle/zoolanding-content-hub"
            or env.get("GITHUB_REF") != "refs/heads/test"
            or env.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or not re.fullmatch(r"[a-f0-9]{40}", env.get("GITHUB_SHA", ""))
            or env.get("EXPECTED_SOURCE_SHA") != env.get("GITHUB_SHA")
            or any(not re.fullmatch(r"[1-9][0-9]*", env.get(key, "")) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
            or any(env.get(key) != REGION for key in ("AWS_REGION", "AWS_DEFAULT_REGION"))):
        raise ReleaseBlocked("test_release_context_invalid")


def review_change_set(description: dict, arn: str, name: str, parameters: list[dict], operation: str, live_processed=None, candidate_processed=None, inventory=None) -> str:
    """Reuse the ordinary identity checks without relaxing its deletion policy."""
    if (not isinstance(description, dict) or description.get("NextToken")
            or not re.fullmatch(rf"arn:aws:cloudformation:{REGION}:[0-9]{{12}}:changeSet/{re.escape(name)}/[A-Za-z0-9-]+", arn)):
        raise ReleaseBlocked("change_set_identity_invalid")
    changes = description.get("Changes") or []
    review_resources(changes, operation, live_processed, candidate_processed, inventory)
    # Ordinary review sees already-checked removal entries as non-replacing updates.
    # Its shared identity, status and parameter validation remains untouched.
    normalized = deepcopy(description)
    for change in normalized.get("Changes") or []:
        if change["ResourceChange"].get("Action") == "Remove":
            change["ResourceChange"]["Action"] = "Modify"
    expected = {p["ParameterKey"]: p["ParameterValue"] for p in parameters if "ParameterValue" in p}
    sensitive = set()
    required = {p["ParameterKey"] for p in parameters}
    expected = {k: v for k, v in expected.items() if k not in sensitive}
    try:
        actual = ordinary_review._parameter_map(description.get("Parameters"))
        if not required.issubset(actual):
            raise ReleaseBlocked("change_set_parameters_missing")
        return ordinary_review.review_change_set(normalized, expected_stack_name=STACK,
            expected_change_set_name=name, expected_change_set_arn=arn, expected_change_set_type="UPDATE",
            expected_parameters=expected, required_parameters=required)
    except ordinary_review.ChangeSetReviewError:
        raise ReleaseBlocked("change_set_review_failed") from None


def _plain_template_value(value: Any) -> Any:
    """Copy SDK maps with JSON object semantics; preserve arrays and scalar types."""
    if isinstance(value, dict):
        return {key: _plain_template_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_plain_template_value(item) for item in value]
    return deepcopy(value)


def _load_template(body: Any) -> dict:
    if isinstance(body, dict):
        return _plain_template_value(body)
    import yaml
    try:
        result = yaml.safe_load(body)
    except (yaml.YAMLError, TypeError):
        raise ReleaseBlocked("template_decode_failed") from None
    if not isinstance(result, dict):
        raise ReleaseBlocked("template_decode_failed")
    return result


def _inventory(cfn: Any, stack_id: str = STACK) -> dict[str, dict]:
    result = {}
    token = None
    while True:
        page = cfn.list_stack_resources(StackName=stack_id, **({"NextToken": token} if token else {}))
        for item in page.get("StackResourceSummaries", []):
            if item.get("ResourceStatus") == "DELETE_COMPLETE":
                continue
            key = item.get("LogicalResourceId")
            if not isinstance(key, str) or key in result or not item.get("PhysicalResourceId"):
                raise ReleaseBlocked("resource_inventory_invalid")
            result[key] = {k: item.get(k) for k in ("PhysicalResourceId", "ResourceType")}
        token = page.get("NextToken")
        if not token:
            return result


def _package_template(build: Path, bucket: str, prefix: str, *, registry_only: bool = False) -> dict:
    with tempfile.TemporaryDirectory(prefix="thn-package-") as temporary:
        destination = Path(temporary) / "packaged.yaml"
        source = build / "template.yaml"
        if registry_only:
            from tools import thn_registry_provision as registry
            projected = registry.packaging_source(_load_template(source.read_text(encoding="utf-8")))
            uri = projected["Resources"][registry.FUNCTION]["Properties"]["CodeUri"]
            if (not isinstance(uri, str) or Path(uri).parts != (registry.FUNCTION,)
                    or not (build / uri).is_dir() or (build / uri).is_symlink()):
                raise ReleaseBlocked("registry_build_path_invalid")
            projected["Resources"][registry.FUNCTION]["Properties"]["CodeUri"] = str((build / uri).resolve())
            source = Path(temporary) / "registry.json"
            source.write_text(json.dumps(projected), encoding="utf-8")
        result = subprocess.run(["sam", "package", "--template-file", str(source),
            "--s3-bucket", bucket, "--s3-prefix", prefix, "--region", REGION,
            "--output-template-file", str(destination)], capture_output=True, text=True, check=False)
        if result.returncode:
            raise ReleaseBlocked("artifact_packaging_failed")
        return _load_template(destination.read_text(encoding="utf-8"))


def verify_dependencies(session: Any, operation: str, values: dict, account: str) -> str:
    """Read the exact ledger; never mutate writers, epochs, descriptors or Auth."""
    if operation not in {"enable", "disable"}:
        raise ReleaseBlocked("dependency_operation_invalid")
    from boto3.dynamodb.types import TypeDeserializer
    response = session.client("dynamodb", region_name=REGION).get_item(
        TableName=REGISTRY_TABLE, ConsistentRead=True,
        Key={"pk": {"S": "SERVICE_BINDING#test#thn-journal-test-v2"}, "sk": {"S": "REGISTRY#V2"}})
    try:
        row = {key: TypeDeserializer().deserialize(value) for key, value in response["Item"].items()}
        fields = set(SCOPE) | {"pk", "sk", "recordType", "schemaVersion", "reservationOwner", "descriptorVersionId", "descriptorSha256",
                              "authPolicyVersion", "activationStatus", "writerMode", "writerEpoch", "registryRevision", "adminOrigin", "cookieNamespace", "resourceBindings"}
        if (set(row) != fields or any(row.get(key) != value for key, value in SCOPE.items())
                or row.get("reservationOwner") != SCOPE
                or row.get("recordType") != "service-binding-registry-v2" or row.get("schemaVersion") != 2
                or row.get("pk") != "SERVICE_BINDING#test#thn-journal-test-v2" or row.get("sk") != "REGISTRY#V2"
                or row.get("adminOrigin") != "https://admin-test.thehairnarrative.com"
                or row.get("cookieNamespace") != "endefiz7dkk635k6di6k"
                or row.get("writerMode") != "disabled"):
            raise ValueError()
        for key in ("writerEpoch", "registryRevision"):
            value = row.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, Decimal)) or value < 1 or value != int(value):
                raise ValueError()
        for key in ("descriptorVersionId", "descriptorSha256", "authPolicyVersion"):
            parameter = "ThnContentHubV2" + key[0].upper() + key[1:]
            if row.get(key) != values.get(parameter) or row.get(key) in {None, "BLOCKED", "0" * 64}:
                raise ValueError()
        bindings = row.get("resourceBindings", {})
        if (not isinstance(bindings, dict) or set(bindings) != {"authoringFunctionArn", "metadataTableArn"}
                or bindings.get("authoringFunctionArn") != f"arn:aws:lambda:{REGION}:{account}:function:zoolanding-content-hub-test-ThnContentHubV2Authoring"
                or bindings.get("metadataTableArn") != f"arn:aws:dynamodb:{REGION}:{account}:table/zoolanding-content-hub-test-ThnContentHubV2Metadata"):
            raise ValueError()
        if operation == "enable":
            if row.get("activationStatus") != "active":
                raise ValueError()
            cfn = session.client("cloudformation", region_name=REGION)
            stacks = cfn.describe_stacks(StackName="zoolanding-auth-admin-test")["Stacks"]
            if len(stacks) != 1:
                raise ValueError()
            auth = stacks[0]
            if (auth.get("StackName") != "zoolanding-auth-admin-test"
                    or re.fullmatch(rf"arn:aws:cloudformation:{REGION}:{account}:stack/zoolanding-auth-admin-test/[A-Za-z0-9-]+", auth.get("StackId", "")) is None
                    or auth.get("EnableTerminationProtection") is not True
                    or auth.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}):
                raise ValueError()
            auth_values = _parameters(auth)
            if (auth_values.get("EnvironmentName") != "test" or auth_values.get("EnableThnAuthAdminV2") != "true"
                    or auth_values.get("ThnAuthAdminV2OriginHeaderSha256Current") in {None, "", "BLOCKED", "0" * 64}):
                raise ValueError()
            for field in ("DescriptorVersionId", "DescriptorSha256", "AuthPolicyVersion"):
                if auth_values.get("ThnAuthAdminV2" + field) != values.get("ThnContentHubV2" + field):
                    raise ValueError()
            resources = cfn.list_stack_resources(StackName="zoolanding-content-hub-test")
            if resources.get("NextToken"):
                raise ValueError()
            roles = [item for item in resources.get("StackResourceSummaries", [])
                     if item.get("LogicalResourceId") == "ThnContentHubV2AuthoringRole"]
            if (len(roles) != 1 or roles[0].get("ResourceType") != "AWS::IAM::Role"
                    or roles[0].get("PhysicalResourceId") != "zlp-thn-ch-test-authoring"
                    or roles[0].get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}):
                raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise ReleaseBlocked("exact_registry_auth_dependency_mismatch") from None
    if operation == "enable":
        cfn = session.client("cloudformation", region_name=REGION)
        images = cfn.describe_stacks(StackName="zoolanding-image-upload-test")["Stacks"]
        if len(images) != 1:
            raise ReleaseBlocked("private_image_stack_required")
        image = images[0]
        image_values = _parameters(image)
        if (image.get("StackName") != "zoolanding-image-upload-test"
                or re.fullmatch(rf"arn:aws:cloudformation:{REGION}:{account}:stack/zoolanding-image-upload-test/[A-Za-z0-9-]+", image.get("StackId", "")) is None
                or image.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}
                or image.get("EnableTerminationProtection") is not True
                or image_values.get("EnableThnPrivateUploadV2") != "true" or image_values.get("ProvisionThnPrivateUploadV2State") != "true"
                or any(image_values.get("ThnContentHubV2" + key) != values.get("ThnContentHubV2" + key)
                       for key in ("DescriptorVersionId", "DescriptorSha256", "AuthPolicyVersion"))):
            raise ReleaseBlocked("private_image_runtime_dependency_mismatch")
        function = f"arn:aws:lambda:{REGION}:{account}:function:zoolanding-image-upload-test-ThnImageUploadV2"
        client = session.client("lambda", region_name=REGION)
        concurrency = client.get_function_concurrency(FunctionName=function).get("ReservedConcurrentExecutions")
        alias = client.get_alias(FunctionName=function, Name="test")
        if (type(concurrency) is not int or concurrency != 2 or alias.get("AliasArn") != function + ":test"
                or alias.get("Name") != "test" or not re.fullmatch(r"[1-9][0-9]*", str(alias.get("FunctionVersion", "")))
                or alias.get("RoutingConfig", {}).get("AdditionalVersionWeights")):
            raise ReleaseBlocked("private_image_alias_dependency_mismatch")
        role_name = "zoolanding-thn-content-hub-test-operator"
        role = session.client("iam").get_role(RoleName=role_name)["Role"]
        if role.get("RoleName") != role_name or role.get("Arn") != f"arn:aws:iam::{account}:role/{role_name}":
            raise ReleaseBlocked("emergency_operator_dependency_mismatch")
    return hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def verify_shared_base(inventory: dict) -> None:
    required = {"ServiceBindingRegistryV2Table": "AWS::DynamoDB::Table", "ContentHubMetadataTable": "AWS::DynamoDB::Table",
                "ContentHubPackagesBucket": "AWS::S3::Bucket", "ContentHubApi": "AWS::ApiGatewayV2::Api"}
    if any(inventory.get(key, {}).get("ResourceType") != kind or not inventory[key].get("PhysicalResourceId") for key, kind in required.items()):
        raise ReleaseBlocked("existing_shared_base_required; generic_resources_cannot_be_bootstrapped_here")
    if inventory["ServiceBindingRegistryV2Table"]["PhysicalResourceId"] != REGISTRY_TABLE:
        raise ReleaseBlocked("existing_registry_identity_mismatch")


def verify_processed(live: dict, candidate: dict, inventory: dict) -> None:
    if not isinstance(live, dict) or not isinstance(candidate, dict):
        raise ReleaseBlocked("verified_processed_snapshots_required")
    before, after = live.get("Resources", {}), candidate.get("Resources", {})
    def shared(resources):
        return {key: value for key, value in resources.items() if key != "ContentHubApi" and not _allowed_resource(key, value.get("Type"))}
    if not before or not after or shared(before) != shared(after):
        raise ReleaseBlocked("processed_shared_resource_drift")
    for pair in PAIRS:
        for suffix in ("Function", "Role", "FunctionAliastest"):
            if after.get(PREFIX + pair + suffix, {}).get("Condition") != "IsThnContentHubV2StateProvisioned":
                raise ReleaseBlocked("processed_runtime_retention_mismatch")
    for key, resource in after.items():
        if not _allowed_resource(key, resource.get("Type")):
            continue
        kind = resource["Type"]
        if kind in STATE_TYPES and (resource.get("DeletionPolicy") != "Retain" or resource.get("UpdateReplacePolicy") != "Retain"):
            raise ReleaseBlocked("processed_state_retention_mismatch")
        if kind == "AWS::Lambda::Version" and resource.get("DeletionPolicy") != "Retain":
            raise ReleaseBlocked("processed_version_retention_mismatch")
        if key in SCHEDULES and resource.get("Properties", {}).get("State") != "DISABLED":
            raise ReleaseBlocked("processed_schedule_must_remain_dormant")
    try:
        thn_api_boundary.verify_route_permissions(candidate)
        thn_api_boundary.review_shared_api({"LogicalResourceId": "ContentHubApi", "ResourceType": "AWS::ApiGatewayV2::Api",
            "PhysicalResourceId": inventory.get("ContentHubApi", {}).get("PhysicalResourceId"), "Action": "Modify", "Replacement": "False",
            "Scope": ["Properties"], "Details": [{"Target": {"Attribute": "Properties", "Name": "Body", "RequiresRecreation": "Never"}}]},
            live, candidate, inventory)
    except thn_api_boundary.ApiBoundaryError:
        raise ReleaseBlocked("processed_shared_api_boundary_mismatch") from None


def verify_runtime(session: Any, inventory: dict, template: dict, account: str) -> None:
    resources = template["Resources"]
    client = session.client("lambda", region_name=REGION)
    for pair in PAIRS:
        prefix = PREFIX + pair
        function = resources[prefix + "Function"]["Properties"]["FunctionName"]
        role = resources[prefix + "Role"]["Properties"]["RoleName"]
        if (inventory.get(prefix + "Function") != {"PhysicalResourceId": function, "ResourceType": "AWS::Lambda::Function"}
                or inventory.get(prefix + "Role") != {"PhysicalResourceId": role, "ResourceType": "AWS::IAM::Role"}):
            raise ReleaseBlocked("retained_runtime_identity_mismatch")
        arn = f"arn:aws:lambda:{REGION}:{account}:function:{function}"
        configuration = client.get_function_configuration(FunctionName=arn)
        alias = client.get_alias(FunctionName=arn, Name="test")
        if (configuration.get("State") != "Active" or configuration.get("LastUpdateStatus") != "Successful"
                or configuration.get("Role") != f"arn:aws:iam::{account}:role/{role}"
                or alias.get("AliasArn") != arn + ":test" or alias.get("Name") != "test"
                or not re.fullmatch(r"[1-9][0-9]*", str(alias.get("FunctionVersion", "")))
                or alias.get("RoutingConfig", {}).get("AdditionalVersionWeights")):
            raise ReleaseBlocked("retained_runtime_readback_mismatch")


def _routes(session: Any, inventory: dict) -> dict:
    physical = inventory.get("ContentHubApi", {}).get("PhysicalResourceId")
    if not isinstance(physical, str) or not re.fullmatch(r"[a-z0-9]{10}", physical):
        raise ReleaseBlocked("shared_api_inventory_invalid")
    client = session.client("apigatewayv2", region_name=REGION)
    result, token = {}, None
    while True:
        page = client.get_routes(ApiId=physical, **({"NextToken": token} if token else {}))
        for item in page.get("Items", []):
            key = item.get("RouteKey")
            if not isinstance(key, str) or not item.get("RouteId") or key in result:
                raise ReleaseBlocked("shared_api_route_inventory_invalid")
            result[key] = item
        token = page.get("NextToken")
        if not token:
            return result


def _verify_routes(actual: dict, previous: dict, enabled: bool) -> None:
    keys = {("GET " if path == thn_api_boundary.PATHS[2] else "POST ") + path for path in thn_api_boundary.PATHS}
    if ((set(actual) & keys) != (keys if enabled else set())
            or {key: value for key, value in actual.items() if key not in keys} != {key: value for key, value in previous.items() if key not in keys}):
        raise ReleaseBlocked("shared_api_v1_or_thn_route_readback_mismatch")


def _verify_retained_state(session: Any, inventory: dict, template: dict, account: str) -> None:
    for logical, resource in template.get("Resources", {}).items():
        if not logical.startswith(PREFIX) or resource.get("Type") not in STATE_TYPES:
            continue
        item = inventory.get(logical)
        if not item or item["ResourceType"] != resource["Type"]:
            raise ReleaseBlocked("retained_state_inventory_mismatch")
        resource_type = item["ResourceType"]
        physical = item["PhysicalResourceId"]
        if resource_type == "AWS::DynamoDB::Table":
            if physical != resource["Properties"]["TableName"]:
                raise ReleaseBlocked("retained_table_identity_mismatch")
            client = session.client("dynamodb", region_name=REGION)
            table = client.describe_table(TableName=physical)["Table"]
            backup = client.describe_continuous_backups(TableName=physical)["ContinuousBackupsDescription"]
            if (table.get("TableStatus") != "ACTIVE" or table.get("DeletionProtectionEnabled") is not True
                    or table.get("SSEDescription", {}).get("Status") != "ENABLED"
                    or backup.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus") != "ENABLED"):
                raise ReleaseBlocked("retained_table_protection_mismatch")
        elif resource_type == "AWS::S3::Bucket":
            client = session.client("s3", region_name=REGION)
            request = {"Bucket": physical, "ExpectedBucketOwner": account}
            versioning = client.get_bucket_versioning(**request)
            public = client.get_public_access_block(**request)["PublicAccessBlockConfiguration"]
            encryption = client.get_bucket_encryption(**request)["ServerSideEncryptionConfiguration"]["Rules"]
            if (versioning.get("Status") != "Enabled"
                    or any(public.get(key) is not True for key in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"))
                    or not encryption or any(rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") != "AES256" for rule in encryption)):
                raise ReleaseBlocked("retained_bucket_protection_mismatch")


def run_release(session: Any, env: dict, build: Path, operation: str) -> dict:
    """Run a TEST-only update; the caller must first verify the immutable artifact."""
    if operation == "registry-provision":
        from tools import thn_registry_provision
        return thn_registry_provision.run(session, env, build)
    validate_context(env)
    if operation not in OPERATIONS or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", env.get("ARTIFACTS_BUCKET", "")):
        raise ReleaseBlocked("release_inputs_invalid")
    identity = session.client("sts", region_name=REGION).get_caller_identity()
    validate_deploy_identity(identity)
    cfn = session.client("cloudformation", region_name=REGION)
    before = cfn.describe_stacks(StackName=STACK)["Stacks"][0]
    validate_stack(before, identity["Account"], expected_account_hash=ACCOUNT_HASH)
    parameters = lifecycle_parameters(before, operation, env.get("THN_V2_TEST_PARAMETERS_JSON"))
    effective = {**_parameters(before), **{p["ParameterKey"]: p["ParameterValue"] for p in parameters if "ParameterValue" in p}}
    dependency_proof = verify_dependencies(session, operation, effective, identity["Account"]) if operation in {"enable", "disable"} else None
    previous = _load_template(cfn.get_template(StackName=STACK, TemplateStage="Original")["TemplateBody"])
    live_processed = _load_template(cfn.get_template(StackName=STACK, TemplateStage="Processed")["TemplateBody"])
    initial_inventory = _inventory(cfn)
    verify_shared_base(initial_inventory)
    original_routes = _routes(session, initial_inventory)
    _verify_routes(original_routes, original_routes, _parameters(before).get(ENABLE) == "true")
    if operation in {"enable", "disable"}:
        _verify_retained_state(session, initial_inventory, previous, identity["Account"])
        verify_runtime(session, initial_inventory, previous, identity["Account"])
    prefix = f"{STACK}/thn/{env['GITHUB_RUN_ID']}/{env['GITHUB_RUN_ATTEMPT']}/{env['GITHUB_SHA']}"
    candidate = previous if operation == "disable" else _package_template(build, env["ARTIFACTS_BUCKET"], prefix)
    template = compose_template(candidate, previous, operation, live_processed)
    expected_readback = effective_parameters(template, _parameters(before), parameters)
    serialized = json.dumps(template, sort_keys=True, separators=(",", ":")).encode()
    key = prefix + "/template-" + hashlib.sha256(serialized).hexdigest() + ".json"
    session.client("s3", region_name=REGION).put_object(Bucket=env["ARTIFACTS_BUCKET"], Key=key,
        Body=serialized, ContentType="application/json", ServerSideEncryption="AES256",
        ExpectedBucketOwner=identity["Account"])
    name = f"thn-{env['GITHUB_RUN_ID']}-{env['GITHUB_RUN_ATTEMPT']}"
    arguments = {"StackName": STACK, "ChangeSetName": name, "ChangeSetType": "UPDATE",
        "TemplateURL": f"https://s3.{REGION}.amazonaws.com/{env['ARTIFACTS_BUCKET']}/{key}",
        "Parameters": parameters, "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        "Description": f"THN TEST {operation} source {env['GITHUB_SHA']}", "ClientToken": name}
    created = cfn.create_change_set(**arguments)
    change_id = created.get("Id")
    if (created.get("StackId") != before["StackId"] or not isinstance(change_id, str)
            or not re.fullmatch(rf"arn:aws:cloudformation:{REGION}:{identity['Account']}:changeSet/{name}/[A-Za-z0-9-]+", change_id)):
        raise ReleaseBlocked("change_set_creation_identity_mismatch")
    executed = False
    try:
        for attempt in range(120):
            description = cfn.describe_change_set(StackName=STACK, ChangeSetName=change_id)
            if description.get("Status") not in {"CREATE_PENDING", "CREATE_IN_PROGRESS"}:
                break
            time.sleep(5)
        else:
            raise ReleaseBlocked("change_set_creation_timeout")
        if description.get("StackId") != before["StackId"]:
            raise ReleaseBlocked("change_set_stack_identity_mismatch")
        if ordinary_review._parameter_map(description.get("Parameters")) != expected_readback:
            raise ReleaseBlocked("change_set_full_parameter_drift")
        candidate_original = _load_template(cfn.get_template(StackName=STACK, ChangeSetName=change_id, TemplateStage="Original")["TemplateBody"])
        candidate_processed = _load_template(cfn.get_template(StackName=STACK, ChangeSetName=change_id, TemplateStage="Processed")["TemplateBody"])
        if candidate_original != template:
            raise ReleaseBlocked("change_set_template_hash_mismatch")
        verify_processed(live_processed, candidate_processed, initial_inventory)
        decision = review_change_set(description, change_id, name, parameters, operation, live_processed, candidate_processed, initial_inventory)
        if decision == "noop":
            _verify_retained_state(session, initial_inventory, template, identity["Account"])
            verify_runtime(session, initial_inventory, template, identity["Account"])
            _verify_routes(_routes(session, initial_inventory), original_routes, effective[ENABLE] == "true")
            if dependency_proof is not None and verify_dependencies(session, operation, effective, identity["Account"]) != dependency_proof:
                raise ReleaseBlocked("registry_changed_during_review")
            return {"operation": operation, "decision": "noop", "retained_state_verified": True}
        current = cfn.describe_stacks(StackName=STACK)["Stacks"][0]
        validate_stack(current, identity["Account"], expected_account_hash=ACCOUNT_HASH)
        if (_parameters(current) != _parameters(before) or _inventory(cfn) != initial_inventory
                or _load_template(cfn.get_template(StackName=STACK, TemplateStage="Original")["TemplateBody"]) != previous
                or _load_template(cfn.get_template(StackName=STACK, TemplateStage="Processed")["TemplateBody"]) != live_processed
                or _routes(session, initial_inventory) != original_routes):
            raise ReleaseBlocked("stack_changed_during_review")
        if dependency_proof is not None and verify_dependencies(session, operation, effective, identity["Account"]) != dependency_proof:
            raise ReleaseBlocked("registry_changed_during_review")
        cfn.execute_change_set(StackName=STACK, ChangeSetName=change_id, ClientRequestToken=name)
        executed = True
        cfn.get_waiter("stack_update_complete").wait(StackName=STACK, WaiterConfig={"Delay": 10, "MaxAttempts": 180})
        for observation in range(2):
            if observation:
                time.sleep(5)
            after = cfn.describe_stacks(StackName=STACK)["Stacks"][0]
            validate_stack(after, identity["Account"], expected_account_hash=ACCOUNT_HASH)
            actual = _parameters(after)
            if actual != expected_readback:
                raise ReleaseBlocked("deployed_full_parameter_mismatch")
            for parameter in parameters:
                key_name = parameter["ParameterKey"]
                expected = parameter.get("ParameterValue", _parameters(before).get(key_name))
                if actual.get(key_name) != expected:
                    raise ReleaseBlocked("deployed_parameter_mismatch")
            inventory = _inventory(cfn)
            for logical, item in initial_inventory.items():
                if (not logical.startswith(PREFIX) or item["ResourceType"] in STATE_TYPES | PERSISTENT_RUNTIME_TYPES) and inventory.get(logical) != item:
                    raise ReleaseBlocked("retained_or_legacy_resource_changed")
            if operation in {"provision", "disable"} and any(item["ResourceType"] in {"AWS::ApiGatewayV2::Api", "AWS::Lambda::Url", "AWS::ApiGatewayV2::Route"}
                    for logical, item in inventory.items() if logical.startswith(PREFIX)):
                raise ReleaseBlocked("disabled_routes_still_present")
            _verify_retained_state(session, inventory, template, identity["Account"])
            verify_runtime(session, inventory, template, identity["Account"])
            _verify_routes(_routes(session, inventory), original_routes, effective[ENABLE] == "true")
            if dependency_proof is not None and verify_dependencies(session, operation, effective, identity["Account"]) != dependency_proof:
                raise ReleaseBlocked("registry_changed_during_release")
        return {"operation": operation, "decision": "executed", "retained_state_verified": True,
                "source_sha": env["GITHUB_SHA"], "template_sha256": hashlib.sha256(serialized).hexdigest()}
    finally:
        if not executed:
            cfn.delete_change_set(StackName=STACK, ChangeSetName=change_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation", choices=sorted(OPERATIONS | {"registry-provision"}), required=True)
    parser.add_argument("--build", type=Path, default=Path(".aws-sam/build"))
    args = parser.parse_args()
    try:
        import boto3
        result = run_release(boto3.Session(region_name=REGION), dict(os.environ), args.build, args.operation)
    except (ReleaseBlocked, ordinary_review.ChangeSetReviewError) as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        # AWS exceptions can contain parameter values and resource identifiers.
        print("thn_test_release_failed; access remains subject to the independent registry gate", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    # Registry helpers import this module by its package name. Use that same
    # module at the file entrypoint so its safe exception class is not duplicated.
    from tools.thn_test_release import main as package_main
    raise SystemExit(package_main())
