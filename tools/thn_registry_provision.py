"""Separate closed five-resource registry bootstrap for the existing Hub TEST stack."""

from copy import deepcopy
import hashlib
import json
import re
import time
from tools import thn_test_release as release

RESOURCE_TYPES = {"ServiceBindingRegistryV2Table": "AWS::DynamoDB::Table",
    "ServiceBindingRegistryV2MutationRole": "AWS::IAM::Role",
    "ServiceBindingRegistryV2MutationFunction": "AWS::Serverless::Function",
    "ServiceBindingRegistryOperatorInvokePolicy": "AWS::IAM::Policy",
    "ServiceBindingRegistryOperatorInvokePermission": "AWS::Lambda::Permission"}
PARAMETER = "ServiceBindingRegistryOperatorRoleArn"
OPERATOR = "zoolanding-thn-registry-test-operator"
FUNCTION = "ServiceBindingRegistryV2MutationFunction"
FUNCTION_NAME = "zoolanding-content-hub-test-ThnServiceBindingRegistryV2Mutation"
ROLE = "ServiceBindingRegistryV2MutationRole"
ROLE_NAME = "zoolanding-thn-registry-test-mutation"
CONDITIONS = {
    "IsTestEnvironment": {"Fn::Equals": [{"Ref": "EnvironmentName"}, "test"]},
    "HasServiceBindingRegistryOperatorRole": {"Fn::And": [{"Condition": "IsTestEnvironment"},
        {"Fn::Equals": [{"Ref": PARAMETER}, {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/" + OPERATOR}]}]},
}


def parameters(stack: dict, operator_arn: str) -> list[dict]:
    previous = release._parameters(stack)
    parts = str(stack.get("StackId", "")).split(":")
    account = parts[4] if len(parts) > 4 else ""
    if (re.fullmatch(r"[0-9]{12}", account) is None
            or operator_arn != f"arn:aws:iam::{account}:role/{OPERATOR}"
            or previous.get("EnvironmentName") != "test" or PARAMETER in previous
            or any(key.startswith(("Thn", "EnableThn", "ProvisionThn")) for key in previous)):
        raise release.ReleaseBlocked("registry_bootstrap_parameters_invalid")
    return ([{"ParameterKey": key, "UsePreviousValue": True} for key in sorted(previous)]
            + [{"ParameterKey": PARAMETER, "ParameterValue": operator_arn}])


def _baseline(live: dict, processed: dict, inventory: dict) -> None:
    if (not isinstance(live, dict) or not isinstance(processed, dict) or not isinstance(inventory, dict)
            or len(inventory) != 17 or set(processed.get("Resources", {})) != set(inventory)
            or not {"ContentHubApi", "ContentHubMetadataTable", "ContentHubPackagesBucket"}.issubset(inventory)):
        raise release.ReleaseBlocked("verified_registry_bootstrap_baseline_required")
    for key, item in inventory.items():
        if (key.startswith(("Thn", "ServiceBindingRegistry")) or not item.get("PhysicalResourceId")
                or processed["Resources"][key].get("Type") != item.get("ResourceType")):
            raise release.ReleaseBlocked("registry_bootstrap_baseline_mismatch")
    for section in ("Resources", "Parameters", "Conditions"):
        if any(key.startswith(("Thn", "EnableThn", "ProvisionThn", "IsThn", "ServiceBindingRegistry", "HasServiceBindingRegistry"))
               for key in live.get(section, {})):
            raise release.ReleaseBlocked("registry_bootstrap_requires_legacy_baseline")


def _validate_slice(template: dict, *, processed: bool = False) -> None:
    resources = template.get("Resources", {})
    for key, source_kind in RESOURCE_TYPES.items():
        kind = "AWS::Lambda::Function" if processed and source_kind == "AWS::Serverless::Function" else source_kind
        resource = resources.get(key, {})
        condition = "HasServiceBindingRegistryOperatorRole" if key.startswith("ServiceBindingRegistryOperator") else "IsTestEnvironment"
        if resource.get("Type") != kind or resource.get("Condition") != condition:
            raise release.ReleaseBlocked("registry_bootstrap_resource_invalid")
    if any(template.get("Conditions", {}).get(key) != value for key, value in CONDITIONS.items()):
        raise release.ReleaseBlocked("registry_bootstrap_condition_invalid")
    table = resources["ServiceBindingRegistryV2Table"]
    properties = table.get("Properties", {})
    if (table.get("DeletionPolicy") != "Retain" or table.get("UpdateReplacePolicy") != "Retain"
            or properties.get("TableName") != release.REGISTRY_TABLE or properties.get("DeletionProtectionEnabled") is not True
            or properties.get("SSESpecification") != {"SSEEnabled": True}
            or properties.get("PointInTimeRecoverySpecification") != {"PointInTimeRecoveryEnabled": True}):
        raise release.ReleaseBlocked("registry_bootstrap_retention_invalid")
    function = resources[FUNCTION].get("Properties", {})
    if (function.get("FunctionName") != FUNCTION_NAME or function.get("Handler") != "service_binding_registry_operator_lambda.lambda_handler"
            or function.get("Role") != {"Fn::GetAtt": [ROLE, "Arn"]}
            or any(key in function for key in ("Events", "FunctionUrlConfig", "AutoPublishAlias"))):
        raise release.ReleaseBlocked("registry_bootstrap_private_function_invalid")
    if resources[ROLE].get("Properties", {}).get("RoleName") != ROLE_NAME:
        raise release.ReleaseBlocked("registry_bootstrap_role_invalid")
    declaration = template.get("Parameters", {}).get(PARAMETER, {})
    if declaration.get("Type") != "String" or declaration.get("Default") != "":
        raise release.ReleaseBlocked("registry_bootstrap_parameter_invalid")


def packaging_source(candidate: dict) -> dict:
    """Package only the existing mediator; never upload shared/v2 Lambda code."""
    result = {key: deepcopy(candidate[key]) for key in ("AWSTemplateFormatVersion", "Transform", "Globals") if key in candidate}
    result["Resources"] = {key: deepcopy(candidate.get("Resources", {}).get(key, {})) for key in RESOURCE_TYPES}
    result["Parameters"] = {key: deepcopy(candidate.get("Parameters", {}).get(key, {}))
                            for key in ("EnvironmentName", "FunctionMemorySize", PARAMETER)}
    result["Conditions"] = {key: deepcopy(candidate.get("Conditions", {}).get(key, {})) for key in CONDITIONS}
    _validate_slice(result)
    return result


def compose(candidate: dict, live: dict, live_processed: dict, inventory: dict) -> dict:
    _baseline(live, live_processed, inventory)
    _validate_slice(candidate)
    if any(candidate.get(key) != live.get(key) for key in ("Transform", "Globals", "Mappings")):
        raise release.ReleaseBlocked("registry_bootstrap_shared_globals_drift")
    for key in ("EnvironmentName", "FunctionMemorySize"):
        if key not in live.get("Parameters", {}):
            raise release.ReleaseBlocked("registry_bootstrap_shared_parameter_missing")
    result = deepcopy(live)
    result["Resources"].update({key: deepcopy(candidate["Resources"][key]) for key in RESOURCE_TYPES})
    result["Parameters"][PARAMETER] = deepcopy(candidate["Parameters"][PARAMETER])
    for key, value in CONDITIONS.items():
        if key in result.get("Conditions", {}) and result["Conditions"][key] != value:
            raise release.ReleaseBlocked("registry_bootstrap_shared_condition_drift")
        result.setdefault("Conditions", {})[key] = deepcopy(value)
    return result


def _processed_drift(live: dict, candidate: dict) -> str:
    """Bounded structure only: fixed schema names, anonymous indexes, no values."""
    names = frozenset("Resources Properties Parameters Outputs Metadata Mappings Conditions Globals Transform Description "
        "AWSTemplateFormatVersion Default Type Value Ref Fn::GetAtt Fn::Sub Fn::Join Fn::If DependsOn DeletionPolicy "
        "UpdateReplacePolicy Version Statement Effect Action Resource Principal PolicyDocument Role Code S3Bucket S3Key "
        "Environment Variables NoEcho Timeout MemorySize Runtime Handler Body DefinitionBody DefinitionUri Tags Condition "
        "AllowedValues AllowedPattern MinValue MaxValue MinLength MaxLength".split())
    missing = object()
    report = {"differences": [], "truncated": False}

    def kind(value):
        if value is missing:
            return "missing"
        for datatype, label in ((type(None), "null"), (bool, "boolean"), (dict, "object"),
                                (list, "array"), (str, "string"), (int, "number"), (float, "number")):
            if isinstance(value, datatype):
                return label
        return "other"

    def walk(before, after, path):
        if before == after:
            return
        if len(report["differences"]) >= 16:
            report["truncated"] = True
            return
        if len(path) < 24 and isinstance(before, dict) and isinstance(after, dict):
            for index, key in enumerate(sorted(set(before) | set(after))):
                walk(before.get(key, missing), after.get(key, missing),
                     path + [key if key in names else f"[{index}]"])
                if report["truncated"]:
                    break
        elif len(path) < 24 and isinstance(before, list) and isinstance(after, list):
            for index in range(max(len(before), len(after))):
                walk(before[index] if index < len(before) else missing,
                     after[index] if index < len(after) else missing, path + [f"[{index}]"])
                if report["truncated"]:
                    break
        else:
            report["differences"].append({"path": "/" + "/".join(path), "before": kind(before), "after": kind(after)})
            report["truncated"] = report["truncated"] or len(path) >= 24

    walk(live, candidate, [])
    return "registry_bootstrap_shared_processed_drift " + json.dumps(report, separators=(",", ":"))


def verify_processed(live: dict, candidate: dict, inventory: dict) -> None:
    _baseline(live, live, inventory)
    _validate_slice(candidate, processed=True)
    if set(candidate.get("Resources", {})) != set(inventory) | set(RESOURCE_TYPES):
        raise release.ReleaseBlocked("registry_bootstrap_processed_resource_mismatch")
    stripped = deepcopy(candidate)
    for key in RESOURCE_TYPES:
        stripped["Resources"].pop(key)
    stripped["Parameters"].pop(PARAMETER)
    for key in CONDITIONS:
        if key not in live.get("Conditions", {}):
            stripped["Conditions"].pop(key)
    if not stripped["Conditions"] and "Conditions" not in live:
        stripped.pop("Conditions")
    if stripped != live:
        raise release.ReleaseBlocked(_processed_drift(live, stripped))


def review_changes(changes: list) -> None:
    if not isinstance(changes, list) or len(changes) != 5:
        raise release.ReleaseBlocked("registry_bootstrap_five_additions_required")
    seen = set()
    for item in changes:
        resource = item.get("ResourceChange", {}) if isinstance(item, dict) else {}
        logical = resource.get("LogicalResourceId")
        expected = RESOURCE_TYPES.get(logical)
        expected = "AWS::Lambda::Function" if expected == "AWS::Serverless::Function" else expected
        if (not isinstance(item, dict) or item.get("Type") != "Resource" or logical in seen or expected is None
                or resource.get("ResourceType") != expected or resource.get("Action") != "Add"
                or resource.get("Replacement") not in (None, "False")):
            raise release.ReleaseBlocked("registry_bootstrap_non_addition_forbidden")
        seen.add(logical)
    if seen != set(RESOURCE_TYPES):
        raise release.ReleaseBlocked("registry_bootstrap_five_additions_required")


def _verify_state(session, inventory: dict, account: str) -> None:
    physical = {"ServiceBindingRegistryV2Table": release.REGISTRY_TABLE, ROLE: ROLE_NAME, FUNCTION: FUNCTION_NAME}
    if any(inventory.get(key, {}).get("PhysicalResourceId") != value for key, value in physical.items()):
        raise release.ReleaseBlocked("registry_bootstrap_physical_identity_mismatch")
    dynamodb = session.client("dynamodb", region_name=release.REGION)
    table = dynamodb.describe_table(TableName=release.REGISTRY_TABLE)["Table"]
    backup = dynamodb.describe_continuous_backups(TableName=release.REGISTRY_TABLE)["ContinuousBackupsDescription"]
    if (table.get("TableName") != release.REGISTRY_TABLE or table.get("TableStatus") != "ACTIVE"
            or table.get("DeletionProtectionEnabled") is not True
            or table.get("SSEDescription", {}).get("Status") != "ENABLED"
            or backup.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus") != "ENABLED"):
        raise release.ReleaseBlocked("registry_bootstrap_retained_state_unverified")
    function = session.client("lambda", region_name=release.REGION).get_function_configuration(FunctionName=FUNCTION_NAME)
    if (function.get("FunctionName") != FUNCTION_NAME or function.get("State") != "Active"
            or function.get("LastUpdateStatus") != "Successful"
            or function.get("Role") != f"arn:aws:iam::{account}:role/{ROLE_NAME}"):
        raise release.ReleaseBlocked("registry_bootstrap_runtime_unverified")


def _change_set_payload(response: dict) -> dict:
    """Exclude only top-level SDK transport metadata, without mutating the response."""
    return {key: value for key, value in response.items() if key != "ResponseMetadata"}


def run(session, env: dict, build) -> dict:
    """Provision only the missing registry, never its rows or THN consumers."""
    release.validate_context(env)
    if re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", env.get("ARTIFACTS_BUCKET", "")) is None:
        raise release.ReleaseBlocked("registry_bootstrap_artifact_bucket_invalid")
    identity = session.client("sts", region_name=release.REGION).get_caller_identity()
    release.validate_deploy_identity(identity)
    account = identity["Account"]
    cfn = session.client("cloudformation", region_name=release.REGION)
    before = cfn.describe_stacks(StackName=release.STACK)["Stacks"][0]
    release.validate_stack(before, account, expected_account_hash=release.ACCOUNT_HASH)
    stack_id = before["StackId"]
    requested = parameters(before, env.get("THN_REGISTRY_OPERATOR_ROLE_ARN", ""))
    operator = session.client("iam", region_name=release.REGION).get_role(RoleName=OPERATOR)["Role"]
    if operator.get("RoleName") != OPERATOR or operator.get("Arn") != f"arn:aws:iam::{account}:role/{OPERATOR}":
        raise release.ReleaseBlocked("registry_bootstrap_operator_missing")
    original = release._load_template(cfn.get_template(StackName=stack_id, TemplateStage="Original")["TemplateBody"])
    processed = release._load_template(cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"])
    inventory = release._inventory(cfn, stack_id)
    _baseline(original, processed, inventory)
    prefix = f"{release.STACK}/thn/{env['GITHUB_RUN_ID']}/{env['GITHUB_RUN_ATTEMPT']}/{env['GITHUB_SHA']}"
    candidate = release._package_template(build, env["ARTIFACTS_BUCKET"], prefix, registry_only=True)
    composed = compose(candidate, original, processed, inventory)
    effective = release.effective_parameters(composed, release._parameters(before), requested)
    serialized = json.dumps(composed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(serialized).hexdigest()
    key = prefix + "/registry-template-" + digest + ".json"
    session.client("s3", region_name=release.REGION).put_object(Bucket=env["ARTIFACTS_BUCKET"], Key=key,
        Body=serialized, ContentType="application/json", ServerSideEncryption="AES256", ExpectedBucketOwner=account)
    name = f"thn-registry-{env['GITHUB_RUN_ID']}-{env['GITHUB_RUN_ATTEMPT']}"
    arguments = {"StackName": stack_id, "ChangeSetName": name, "ChangeSetType": "UPDATE", "IncludeNestedStacks": False,
        "TemplateURL": f"https://s3.{release.REGION}.amazonaws.com/{env['ARTIFACTS_BUCKET']}/{key}",
        "Parameters": requested, "Capabilities": ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        "Description": f"THN registry bootstrap source {env['GITHUB_SHA']}", "ClientToken": name}
    created = cfn.create_change_set(**arguments)
    change_id = created.get("Id")
    if (created.get("StackId") != stack_id or not isinstance(change_id, str)
            or re.fullmatch(rf"arn:aws:cloudformation:{release.REGION}:{account}:changeSet/{name}/[A-Za-z0-9-]+", change_id) is None):
        raise release.ReleaseBlocked("registry_bootstrap_change_set_identity_mismatch")
    executed = False
    try:
        for attempt in range(120):
            description = cfn.describe_change_set(StackName=stack_id, ChangeSetName=change_id)
            if description.get("Status") not in {"CREATE_PENDING", "CREATE_IN_PROGRESS"}:
                break
            time.sleep(5)
        else:
            raise release.ReleaseBlocked("registry_bootstrap_change_set_timeout")
        review_changes(description.get("Changes"))
        if (description.get("StackId") != stack_id or description.get("NextToken")
                or release.ordinary_review._parameter_map(description.get("Parameters")) != effective):
            raise release.ReleaseBlocked("registry_bootstrap_review_identity_mismatch")
        decision = release.ordinary_review.review_change_set(description, expected_stack_name=release.STACK,
            expected_change_set_name=name, expected_change_set_arn=change_id, expected_change_set_type="UPDATE",
            expected_parameters=effective, required_parameters=set(effective))
        if decision != "execute":
            raise release.ReleaseBlocked("registry_bootstrap_requires_five_new_resources")
        candidate_original = release._load_template(cfn.get_template(StackName=stack_id, ChangeSetName=change_id, TemplateStage="Original")["TemplateBody"])
        candidate_processed = release._load_template(cfn.get_template(StackName=stack_id, ChangeSetName=change_id, TemplateStage="Processed")["TemplateBody"])
        if candidate_original != composed:
            raise release.ReleaseBlocked("registry_bootstrap_template_hash_mismatch")
        verify_processed(processed, candidate_processed, inventory)
        current = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        release.validate_stack(current, account, expected_account_hash=release.ACCOUNT_HASH)
        if (current.get("StackId") != stack_id or current.get("RoleARN") != before.get("RoleARN")
                or release._parameters(current) != release._parameters(before) or release._inventory(cfn, stack_id) != inventory
                or release._load_template(cfn.get_template(StackName=stack_id, TemplateStage="Original")["TemplateBody"]) != original
                or release._load_template(cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"]) != processed
                or _change_set_payload(cfn.describe_change_set(StackName=stack_id, ChangeSetName=change_id))
                    != _change_set_payload(description)
                or release._load_template(cfn.get_template(StackName=stack_id, ChangeSetName=change_id, TemplateStage="Original")["TemplateBody"]) != composed
                or release._load_template(cfn.get_template(StackName=stack_id, ChangeSetName=change_id, TemplateStage="Processed")["TemplateBody"]) != candidate_processed):
            raise release.ReleaseBlocked("registry_bootstrap_changed_during_review")
        cfn.execute_change_set(StackName=stack_id, ChangeSetName=change_id, ClientRequestToken=name)
        executed = True
        cfn.get_waiter("stack_update_complete").wait(StackName=stack_id, WaiterConfig={"Delay": 10, "MaxAttempts": 180})
        expected_types = {key: item["ResourceType"] for key, item in inventory.items()}
        expected_types.update({key: "AWS::Lambda::Function" if kind == "AWS::Serverless::Function" else kind for key, kind in RESOURCE_TYPES.items()})
        for observation in range(2):
            if observation:
                time.sleep(5)
            after = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
            release.validate_stack(after, account, expected_account_hash=release.ACCOUNT_HASH)
            final_inventory = release._inventory(cfn, stack_id)
            if (after.get("StackId") != stack_id or after.get("RoleARN") != before.get("RoleARN")
                    or release._parameters(after) != effective
                    or {key: item["ResourceType"] for key, item in final_inventory.items()} != expected_types
                    or any(final_inventory.get(key) != value for key, value in inventory.items())
                    or release._load_template(cfn.get_template(StackName=stack_id, TemplateStage="Original")["TemplateBody"]) != composed
                    or release._load_template(cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"]) != candidate_processed):
                raise release.ReleaseBlocked("registry_bootstrap_final_inventory_mismatch")
            _verify_state(session, final_inventory, account)
        return {"operation": "registry-provision", "decision": "executed", "preserved_resource_count": 17,
                "new_resource_count": 5, "thn_runtime_resource_count": 0, "retained_state_verified": True,
                "source_sha": env["GITHUB_SHA"], "template_sha256": digest}
    finally:
        if not executed:
            cfn.delete_change_set(StackName=stack_id, ChangeSetName=change_id)
