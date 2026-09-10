#!/usr/bin/env python3
"""Materialize fail-closed Content Hub TEST parameters without logging secrets."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Mapping


class ParameterPreparationError(ValueError):
    pass


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ParameterPreparationError(f"{name.lower()}_required")
    return value


def _require_json_base64(value: str) -> None:
    try:
        payload = json.loads(base64.b64decode(value, validate=True).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ParameterPreparationError("content_hub_config_invalid") from exc
    if not isinstance(payload, dict):
        raise ParameterPreparationError("content_hub_config_invalid")


def _table_name(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", value) is None:
        raise ParameterPreparationError("auth_table_name_invalid")
    return value


def _thn_defaults() -> dict[str, str]:
    return {
        "ServiceBindingRegistryOperatorRoleArn": "",
        "EnableThnContentHubV2": "false",
        "ProvisionThnContentHubV2State": "false",
        "ThnContentHubV2TerminationProtectionGate": "BLOCKED",
        "ThnContentHubV2EmergencyOperatorRoleArn": "",
        "ThnContentHubV2PublicDistributionId": "BLOCKED",
        "ThnContentHubV2DescriptorVersionId": "BLOCKED",
        "ThnContentHubV2DescriptorSha256": "0" * 64,
        "ThnContentHubV2AuthPolicyVersion": "BLOCKED",
    }


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ParameterPreparationError("thn_test_selection_invalid")
        result[key] = value
    return result


def _deployment_role(env: Mapping[str, str]) -> tuple[str, str]:
    match = re.fullmatch(
        r"arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+",
        env.get("AWS_ROLE_ARN", ""),
    )
    if match is None:
        raise ParameterPreparationError("thn_test_deployment_role_invalid")
    return match.group(1), match.group(2)


def _thn_parameters(env: Mapping[str, str]) -> dict[str, str]:
    """A complete reviewed selection can change v2 parameters only, never v1."""
    raw = env.get("THN_V2_TEST_PARAMETERS_JSON", "")
    if raw == "":
        return _thn_defaults()
    try:
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 16384:
            raise ValueError()
        envelope = json.loads(raw, object_pairs_hook=_unique_object)
        if (not isinstance(envelope, dict)
                or set(envelope) != {"schemaVersion", "environment", "parameters"}
                or type(envelope["schemaVersion"]) is not int
                or envelope["schemaVersion"] != 1 or envelope["environment"] != "test"):
            raise ValueError()
        values = envelope["parameters"]
        if not isinstance(values, dict) or set(values) != set(_thn_defaults()):
            raise ValueError()
        if any(not isinstance(value, str) or len(value) > 256
               or re.fullmatch(r"[\x20-\x7e]*", value) is None for value in values.values()):
            raise ValueError()
        for key in ("EnableThnContentHubV2", "ProvisionThnContentHubV2State"):
            if values[key] not in {"false", "true"}:
                raise ValueError()
        if values["ThnContentHubV2TerminationProtectionGate"] not in {"BLOCKED", "CONFIRMED_ENABLED"}:
            raise ValueError()
        for key in ("ThnContentHubV2DescriptorVersionId", "ThnContentHubV2AuthPolicyVersion"):
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", values[key]) is None:
                raise ValueError()
        if re.fullmatch(r"[a-f0-9]{64}", values["ThnContentHubV2DescriptorSha256"]) is None:
            raise ValueError()
        if re.fullmatch(r"BLOCKED|[A-Z0-9]{8,32}", values["ThnContentHubV2PublicDistributionId"]) is None:
            raise ValueError()
        partition, account = _deployment_role(env)
        for key, name in (
            ("ServiceBindingRegistryOperatorRoleArn", "zoolanding-thn-registry-test-operator"),
            ("ThnContentHubV2EmergencyOperatorRoleArn", "zoolanding-thn-content-hub-test-operator"),
        ):
            if values[key] not in {"", f"arn:{partition}:iam::{account}:role/{name}"}:
                raise ValueError()
        if values["EnableThnContentHubV2"] == "true":
            if (values["ProvisionThnContentHubV2State"] != "true"
                    or values["ThnContentHubV2TerminationProtectionGate"] != "CONFIRMED_ENABLED"
                    or any(values[key] in {"", "BLOCKED", "0" * 64} for key in (
                        "ServiceBindingRegistryOperatorRoleArn", "ThnContentHubV2EmergencyOperatorRoleArn",
                        "ThnContentHubV2PublicDistributionId", "ThnContentHubV2DescriptorVersionId",
                        "ThnContentHubV2DescriptorSha256", "ThnContentHubV2AuthPolicyVersion"))):
                raise ValueError()
        return dict(values)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ParameterPreparationError("thn_test_selection_invalid") from None


def _aws_cli_read(service: str, operation: str, query: str, *arguments: str):
    """Use the workflow's existing CLI; never print raw cloud errors or values."""
    result = subprocess.run(
        ["aws", service, operation, *arguments, "--query", query, "--region", "us-east-1",
         "--output", "json", "--no-cli-pager"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False,
    )
    if result.returncode or len(result.stdout.encode("utf-8")) > 16384:
        raise ValueError()
    return json.loads(result.stdout)


def verify_cloud_guards(env: Mapping[str, str], *, session=None) -> None:
    """Verify the real account/protection without provisioning or changing state."""
    values = _thn_parameters(env)
    if not env.get("THN_V2_TEST_PARAMETERS_JSON"):
        return
    if any(env.get(key, "us-east-1") != "us-east-1" for key in ("AWS_REGION", "AWS_DEFAULT_REGION")):
        raise ParameterPreparationError("thn_test_region_invalid")
    _, expected_account = _deployment_role(env)
    try:
        identity = (session.client("sts").get_caller_identity() if session is not None
                    else _aws_cli_read("sts", "get-caller-identity", "{Account:Account}"))
        if identity.get("Account") != expected_account:
            raise ValueError()
        if values["EnableThnContentHubV2"] == "true" or values["ProvisionThnContentHubV2State"] == "true":
            stacks = (session.client("cloudformation").describe_stacks(StackName="zoolanding-content-hub-test")["Stacks"]
                      if session is not None else _aws_cli_read(
                          "cloudformation", "describe-stacks",
                          "Stacks[].{StackName:StackName,StackStatus:StackStatus,EnableTerminationProtection:EnableTerminationProtection}",
                          "--stack-name", "zoolanding-content-hub-test"))
            if (len(stacks) != 1 or stacks[0].get("StackName") != "zoolanding-content-hub-test"
                    or stacks[0].get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
                    or stacks[0].get("EnableTerminationProtection") is not True):
                raise ValueError()
    except Exception:
        raise ParameterPreparationError("thn_test_cloud_guard_failed") from None


def build_parameters(env: Mapping[str, str]) -> tuple[dict[str, str], set[str]]:
    if env.get("CONTENT_HUB_CONFIG_READY") != "true":
        raise ParameterPreparationError("content_hub_config_not_ready")
    config = _required(env, "CONTENT_HUB_CONFIG_JSON_BASE64")
    _require_json_base64(config)
    session_table = _table_name(_required(env, "AUTH_SESSION_TABLE_NAME"))
    user_table = _table_name(_required(env, "AUTH_USER_STATE_TABLE_NAME"))
    return {
        "EnvironmentName": "test",
        "ContentHubConfigJsonBase64": config,
        "AuthSessionTableName": session_table,
        "AuthUserStateTableName": user_table,
        "LogLevel": "INFO",
        "FunctionMemorySize": "512",
        **_thn_parameters(env),
    }, {"ContentHubConfigJsonBase64"}


def write_parameter_files(output: Path, parameters: Mapping[str, str], sensitive: set[str]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    if any(not key or not isinstance(value, str) or "\n" in value or "\r" in value for key, value in parameters.items()):
        raise ParameterPreparationError("test_parameter_invalid")
    (output / "parameters.json").write_text(json.dumps([{"ParameterKey": key, "ParameterValue": value} for key, value in parameters.items()], separators=(",", ":")), encoding="utf-8")
    (output / "expected-parameters.txt").write_text("".join(f"{key}={parameters[key]}\n" for key in sorted(parameters) if key not in sensitive), encoding="utf-8")
    (output / "required-parameters.txt").write_text("".join(f"{key}\n" for key in sorted(sensitive) if parameters.get(key)), encoding="utf-8")


def _validate_runtime_config() -> None:
    root = Path(__file__).resolve().parents[1]
    candidates = (root / "ContentHubFunction" / "lambda_function.py", root / "lambda_function.py")
    handler_path = next((path for path in candidates if path.is_file()), None)
    if handler_path is None:
        raise ParameterPreparationError("content_hub_runtime_validator_missing")
    spec = importlib.util.spec_from_file_location("content_hub_release_validator", handler_path)
    if spec is None or spec.loader is None:
        raise ParameterPreparationError("content_hub_runtime_validator_missing")
    sys.path.insert(0, str(handler_path.parent))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.load_config()


def main() -> int:
    if sys.argv[1:] == ["--thn-selection-contract"]:
        print("thn-test-selection/v1")
        return 0
    if sys.argv[1:] == ["--verify-cloud-guards"]:
        verify_cloud_guards(os.environ)
        return 0
    if sys.argv[1:]:
        raise ParameterPreparationError("test_parameter_arguments_invalid")
    parameters, sensitive = build_parameters(os.environ)
    os.environ["CONTENT_HUB_ENVIRONMENT"] = "test"
    _validate_runtime_config()
    write_parameter_files(Path(os.environ["RUNNER_TEMP"]) / "test-release-parameters", parameters, sensitive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
