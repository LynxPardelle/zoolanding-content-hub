#!/usr/bin/env python3
"""Guard one existing THN TEST registry-table reader-policy revision."""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

import boto3
import yaml

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tools import thn_test_release as release


TABLE = "ServiceBindingRegistryV2Table"
SID = "DenyRegistryGetItemOutsideApprovedConsumers"
RUNTIME_ROLE = "zoolanding-thn-auth-runti-ThnAuthRuntimeV2FunctionR-0nd3Hd8ToVOo"
SOURCE = _ROOT / "template.yaml"
EXPECTED_LIVE_POLICY_SHA256 = "a61b8dc3875dc4bdd45b94b7e61d804f351ade628898c31303ac4cb74f34a08c"
DEPLOYMENT_READER_SIDS = (
    "AllowRegistryDeploymentBindingRead",
    "DenyRegistryDeploymentReadOutsideBinding",
    "DenyRegistryDeploymentReadMissingKeys",
)


class RevisionBlocked(release.ReleaseBlocked):
    """Public-safe rejection of a policy-only revision."""


def reject() -> None:
    raise RevisionBlocked("thn_registry_reader_revision_guard_failed")


def runtime_role_intrinsic() -> dict:
    return {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/" + RUNTIME_ROLE}


def reader_list(table: dict) -> list:
    try:
        statements = table["Properties"]["ResourcePolicy"]["PolicyDocument"]["Statement"]
        matches = [item for item in statements if item.get("Sid") == SID]
        if len(matches) != 1 or matches[0]["Action"] != ["dynamodb:GetItem"] or matches[0]["Effect"] != "Deny":
            reject()
        readers = matches[0]["Condition"]["ArnNotEquals"]["aws:PrincipalArn"]
        if not isinstance(readers, list):
            reject()
        return readers
    except (KeyError, TypeError, AttributeError):
        reject()


def compose_revision(live: dict, desired: dict) -> dict:
    """Change only one table policy statement in an exact live template snapshot."""
    try:
        old = deepcopy(live["Resources"][TABLE])
        new = deepcopy(desired["Resources"][TABLE])
        role = runtime_role_intrinsic()
        readers = reader_list(new)
        if (new.get("Type") != "AWS::DynamoDB::Table" or readers.count(role) != 1
                or len(readers) != 13 or len(set(json.dumps(x, sort_keys=True) for x in readers)) != 13):
            reject()
        position = readers.index(role)
        reader_list(new).remove(role)
        annotation = old.pop("Metadata", None)
        if annotation not in (None, {"SamResourceId": TABLE}) or old != new:
            reject()
        result = deepcopy(live)
        reader_list(result["Resources"][TABLE]).insert(
            position, deepcopy(role))
        if result["Resources"][TABLE].get("Metadata") != annotation:
            reject()
        return result
    except (KeyError, TypeError, ValueError):
        reject()


def review_changes(changes: list) -> None:
    """Never execute an add, replacement, shared API edit or second change."""
    if not isinstance(changes, list) or len(changes) != 1:
        reject()
    change = changes[0]
    if not isinstance(change, dict):
        reject()
    resource = change.get("ResourceChange")
    if (change.get("Type") != "Resource" or not isinstance(resource, dict)
            or resource.get("Action") != "Modify" or resource.get("LogicalResourceId") != TABLE
            or resource.get("ResourceType") != "AWS::DynamoDB::Table"
            or resource.get("Replacement") != "False" or resource.get("Scope") != ["Properties"]
            or resource.get("ChangeSetId") or resource.get("ModuleInfo")):
        reject()
    details = resource.get("Details")
    if (not isinstance(details, list) or not details
            or any(not isinstance(item, dict) or item.get("Target", {}).get("Attribute") != "Properties"
                   or item["Target"].get("Name") != "ResourcePolicy"
                   or item["Target"].get("RequiresRecreation") not in (None, "Never") for item in details)):
        reject()


def _policy_readers(dynamodb, account: str) -> tuple[dict, str]:
    arn = f"arn:aws:dynamodb:{release.REGION}:{account}:table/{release.REGISTRY_TABLE}"
    response = dynamodb.get_resource_policy(ResourceArn=arn)
    policy = json.loads(response["Policy"])
    matches = [item for item in policy.get("Statement", []) if item.get("Sid") == SID]
    if len(matches) != 1:
        reject()
    readers = matches[0].get("Condition", {}).get("ArnNotEquals", {}).get("aws:PrincipalArn")
    if not isinstance(readers, list) or len(readers) != 12:
        reject()
    return policy, response["RevisionId"]


def _changed_policy(before: dict, account: str) -> dict:
    after = deepcopy(before)
    matches = [item for item in after["Statement"] if item.get("Sid") == SID]
    if len(matches) != 1:
        reject()
    readers = matches[0]["Condition"]["ArnNotEquals"]["aws:PrincipalArn"]
    role = f"arn:aws:iam::{account}:role/{RUNTIME_ROLE}"
    if role in readers or len(readers) != 12:
        reject()
    readers.insert(2, role)
    return after


def normalized_policy(policy: dict, account: str) -> dict:
    """Ignore only DynamoDB's observed reordering of two exact role principals."""
    result = deepcopy(policy)
    expected = {
        f"arn:aws:iam::{account}:role/zoolanding-content-hub-test-deploy",
        f"arn:aws:iam::{account}:role/zoolanding-deployer-image-upload-test-github-deploy",
    }
    for sid in DEPLOYMENT_READER_SIDS:
        matches = [item for item in result.get("Statement", []) if item.get("Sid") == sid]
        if len(matches) != 1:
            reject()
        principals = matches[0].get("Principal", {}).get("AWS")
        if not isinstance(principals, list) or len(principals) != 2 or set(principals) != expected:
            reject()
        matches[0]["Principal"]["AWS"] = sorted(principals)
    return result


def _unchanged(current: dict, before: dict, cfn, original: dict, processed: dict, inventory: dict) -> None:
    release.validate_stack(current, current["StackId"].split(":")[4])
    if (current["StackId"] != before["StackId"] or current.get("RoleARN") != before.get("RoleARN")
            or release._parameters(current) != release._parameters(before)
            or release._inventory(cfn, before["StackId"]) != inventory
            or release._load_template(cfn.get_template(StackName=before["StackId"], TemplateStage="Original")["TemplateBody"]) != original
            or release._load_template(cfn.get_template(StackName=before["StackId"], TemplateStage="Processed")["TemplateBody"]) != processed):
        reject()


def run(session, env: dict, operation: str) -> dict:
    release.validate_context(env)
    if (operation not in ("verify", "apply") or env.get("GITHUB_ACTIONS") != "true"
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", env.get("ARTIFACTS_BUCKET", ""))):
        reject()
    identity = session.client("sts", region_name=release.REGION).get_caller_identity()
    release.validate_deploy_identity(identity)
    account = identity["Account"]
    cfn = session.client("cloudformation", region_name=release.REGION)
    dynamodb = session.client("dynamodb", region_name=release.REGION)
    s3 = session.client("s3", region_name=release.REGION)
    before = cfn.describe_stacks(StackName=release.STACK)["Stacks"][0]
    release.validate_stack(before, account)
    if before["StackStatus"] != "UPDATE_COMPLETE" or before.get("RoleARN"):
        reject()
    stack_id = before["StackId"]
    original = release._load_template(cfn.get_template(StackName=stack_id, TemplateStage="Original")["TemplateBody"])
    processed = release._load_template(cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"])
    inventory = release._inventory(cfn, stack_id)
    release.verify_shared_base(inventory)
    original_routes = release._routes(session, inventory)
    if inventory[TABLE] != {"PhysicalResourceId": release.REGISTRY_TABLE, "ResourceType": "AWS::DynamoDB::Table"}:
        reject()
    desired = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))
    composed = compose_revision(original, desired)
    expected_processed = compose_revision(processed, desired)
    policy_before, revision_before = _policy_readers(dynamodb, account)
    policy_after = _changed_policy(policy_before, account)
    policy_digest = hashlib.sha256(json.dumps(normalized_policy(policy_before, account),
                                               sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if (policy_digest != EXPECTED_LIVE_POLICY_SHA256
            or inventory["ServiceBindingRegistryV2MutationRole"]["PhysicalResourceId"]
                != "zoolanding-thn-registry-test-mutation"):
        reject()
    params = [{"ParameterKey": key, "UsePreviousValue": True} for key in sorted(release._parameters(before))]
    expected_params = release.effective_parameters(composed, release._parameters(before), params)
    if operation == "verify":
        return {"operation": operation, "decision": "ready", "preserved_resource_count": len(inventory)}
    serialized = json.dumps(composed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(serialized).hexdigest()
    prefix = f"{release.STACK}/thn/registry-reader/{env['GITHUB_RUN_ID']}/{env['GITHUB_RUN_ATTEMPT']}/{env['GITHUB_SHA']}"
    key = prefix + "/template-" + digest + ".json"
    s3.put_object(Bucket=env["ARTIFACTS_BUCKET"], Key=key, Body=serialized,
                  ContentType="application/json", ServerSideEncryption="AES256", ExpectedBucketOwner=account)
    name = f"thn-reader-{env['GITHUB_RUN_ID']}-{env['GITHUB_RUN_ATTEMPT']}"
    created = cfn.create_change_set(StackName=stack_id, ChangeSetName=name, ChangeSetType="UPDATE",
        IncludeNestedStacks=False,
        TemplateURL=f"https://s3.{release.REGION}.amazonaws.com/{env['ARTIFACTS_BUCKET']}/{key}",
        Parameters=params, Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Description=f"THN TEST registry reader source {env['GITHUB_SHA']}", ClientToken=name)
    change_id = created.get("Id")
    if (created.get("StackId") != stack_id or not isinstance(change_id, str)
            or not re.fullmatch(rf"arn:aws:cloudformation:{release.REGION}:{account}:changeSet/{name}/[A-Za-z0-9-]+", change_id)):
        reject()
    executed = False
    retain_failed = False
    try:
        for _ in range(120):
            plan = cfn.describe_change_set(StackName=stack_id, ChangeSetName=change_id)
            if plan.get("Status") not in ("CREATE_PENDING", "CREATE_IN_PROGRESS"):
                break
            time.sleep(5)
        else:
            raise RevisionBlocked("thn_registry_reader_change_set_timeout")
        if plan.get("Status") == "FAILED":
            retain_failed = True
            raise RevisionBlocked("thn_registry_reader_change_set_failed_diagnostic_retained")
        if (plan.get("ChangeSetId") != change_id or plan.get("StackId") != stack_id
                or plan.get("StackName") != release.STACK or plan.get("ChangeSetName") != name
                or plan.get("Status") != "CREATE_COMPLETE" or plan.get("ExecutionStatus") != "AVAILABLE"
                or plan.get("NextToken") or release.ordinary_review._parameter_map(plan.get("Parameters")) != expected_params):
            reject()
        review_changes(plan.get("Changes"))
        plan_original = release._load_template(cfn.get_template(StackName=stack_id, ChangeSetName=change_id,
                                                               TemplateStage="Original")["TemplateBody"])
        plan_processed = release._load_template(cfn.get_template(StackName=stack_id, ChangeSetName=change_id,
                                                                TemplateStage="Processed")["TemplateBody"])
        if plan_original != composed or plan_processed != expected_processed:
            reject()
        _unchanged(cfn.describe_stacks(StackName=stack_id)["Stacks"][0], before, cfn,
                   original, processed, inventory)
        if release._routes(session, inventory) != original_routes:
            reject()
        policy_now, revision_now = _policy_readers(dynamodb, account)
        if normalized_policy(policy_now, account) != normalized_policy(policy_before, account) or revision_now != revision_before:
            reject()
        cfn.execute_change_set(StackName=stack_id, ChangeSetName=change_id, ClientRequestToken=name)
        executed = True
        cfn.get_waiter("stack_update_complete").wait(StackName=stack_id, WaiterConfig={"Delay": 10, "MaxAttempts": 180})
        for observation in range(2):
            if observation:
                time.sleep(5)
            final = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
            release.validate_stack(final, account)
            if (final["StackId"] != stack_id or final["StackStatus"] != "UPDATE_COMPLETE"
                    or release._parameters(final) != expected_params or release._inventory(cfn, stack_id) != inventory
                    or release._load_template(cfn.get_template(StackName=stack_id, TemplateStage="Original")["TemplateBody"]) != composed
                    or release._load_template(cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"]) != expected_processed
                    or release._routes(session, inventory) != original_routes):
                reject()
            current_policy = json.loads(dynamodb.get_resource_policy(
                ResourceArn=f"arn:aws:dynamodb:{release.REGION}:{account}:table/{release.REGISTRY_TABLE}")["Policy"])
            if normalized_policy(current_policy, account) != normalized_policy(policy_after, account):
                reject()
        return {"operation": operation, "decision": "executed", "preserved_resource_count": len(inventory),
                "source_sha": env["GITHUB_SHA"], "template_sha256": digest}
    finally:
        if not executed and not retain_failed:
            cfn.delete_change_set(StackName=stack_id, ChangeSetName=change_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation", choices=["verify", "apply"], required=True)
    args = parser.parse_args()
    try:
        result = run(boto3.Session(region_name=release.REGION), dict(os.environ), args.operation)
        print(json.dumps(result, sort_keys=True))
        return 0
    except RevisionBlocked as error:
        print(str(error), file=sys.stderr)
    except release.ReleaseBlocked:
        print("thn_registry_reader_release_guard_failed", file=sys.stderr)
    except Exception:
        print("thn_registry_reader_release_failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
