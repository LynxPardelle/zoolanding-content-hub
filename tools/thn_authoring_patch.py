#!/usr/bin/env python3
"""Patch only the retained THN TEST authoring code through a guarded change set."""

from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import time
import zipfile

import boto3

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from tools import thn_test_release as release


FUNCTION = "ThnContentHubV2AuthoringFunction"
ALIAS = FUNCTION + "Aliastest"
VERSION_PREFIX = FUNCTION + "Version"
VERSION_PATTERN = re.compile(re.escape(VERSION_PREFIX) + r"[a-f0-9]{10}\Z")


class PatchBlocked(release.ReleaseBlocked):
    """A public-safe authoring-only release rejection."""


def reject() -> None:
    raise PatchBlocked("thn_authoring_patch_guard_failed")


def compose_template(live: dict, code_uri: str) -> dict:
    """Keep every live Original template node except authoring CodeUri."""
    if not isinstance(code_uri, str) or not re.fullmatch(r"s3://[a-z0-9.-]+/[A-Za-z0-9/._-]+", code_uri):
        reject()
    try:
        resource = live["Resources"][FUNCTION]
        previous = resource["Properties"]["CodeUri"]
        if resource["Type"] != "AWS::Serverless::Function" or not isinstance(previous, str) or previous == code_uri:
            reject()
        result = deepcopy(live)
        result["Resources"][FUNCTION]["Properties"]["CodeUri"] = code_uri
        return result
    except (KeyError, TypeError, AttributeError):
        reject()


def _version_ids(resources: dict) -> set[str]:
    ids = {key for key in resources if key.startswith(VERSION_PREFIX)}
    if not ids or any(not VERSION_PATTERN.fullmatch(key) or resources[key].get("Type") != "AWS::Lambda::Version"
                      or resources[key].get("DeletionPolicy") != "Retain" for key in ids):
        reject()
    return ids


def _version_reference(value: object, version: str) -> bool:
    return value in ({"Fn::GetAtt": [version, "Version"]}, {"Ref": version})


def review_processed(live: dict, candidate: dict) -> tuple[str, str]:
    """Accept only transformed code, one new retained version, and alias retarget."""
    try:
        before, after = live["Resources"], candidate["Resources"]
        if {key: value for key, value in live.items() if key != "Resources"} != {
                key: value for key, value in candidate.items() if key != "Resources"}:
            reject()
        old_ids, new_ids = _version_ids(before), _version_ids(after)
        removed, added = old_ids - new_ids, new_ids - old_ids
        if len(removed) != 1 or len(added) != 1 or old_ids & new_ids:
            reject()
        old, new = next(iter(removed)), next(iter(added))
        if set(before) - {old} != set(after) - {new}:
            reject()
        if (before[FUNCTION]["Type"] != "AWS::Lambda::Function"
                or after[FUNCTION]["Type"] != "AWS::Lambda::Function"):
            reject()
        old_function, new_function = deepcopy(before[FUNCTION]), deepcopy(after[FUNCTION])
        old_code = old_function["Properties"].pop("Code")
        new_code = new_function["Properties"].pop("Code")
        if old_function != new_function or old_code == new_code or not isinstance(new_code, dict):
            reject()
        old_alias, new_alias = deepcopy(before[ALIAS]), deepcopy(after[ALIAS])
        old_ref = old_alias["Properties"].pop("FunctionVersion")
        new_ref = new_alias["Properties"].pop("FunctionVersion")
        if (old_alias != new_alias or old_alias.get("Type") != "AWS::Lambda::Alias"
                or not _version_reference(old_ref, old) or not _version_reference(new_ref, new)):
            reject()
        old_version, new_version = before[old], after[new]
        if (old_version != new_version
                or old_version["Properties"].get("FunctionName") != {"Ref": FUNCTION}
                or new_version["Properties"].get("FunctionName") != {"Ref": FUNCTION}
                or old_version.get("Condition") != new_version.get("Condition")):
            reject()
        for logical in set(before) - {FUNCTION, ALIAS, old}:
            if before[logical] != after[logical]:
                reject()
        return old, new
    except (KeyError, TypeError, AttributeError, StopIteration):
        reject()


def _modify(change: dict, logical: str, kind: str, property_name: str) -> None:
    if (change.get("LogicalResourceId") != logical or change.get("ResourceType") != kind
            or change.get("Action") != "Modify" or change.get("Replacement") != "False"
            or change.get("Scope") != ["Properties"] or change.get("ChangeSetId") or change.get("ModuleInfo")):
        reject()
    details = change.get("Details")
    if (not isinstance(details, list) or not details or any(
            not isinstance(item, dict) or item.get("Target", {}).get("Attribute") != "Properties"
            or item["Target"].get("Name") != property_name
            or item["Target"].get("RequiresRecreation") not in (None, "Never") for item in details)):
        reject()


def review_changes(changes: list, old: str, new: str) -> None:
    """Reject all resource actions outside the exact transformed delta."""
    if (not VERSION_PATTERN.fullmatch(old) or not VERSION_PATTERN.fullmatch(new) or old == new
            or not isinstance(changes, list) or len(changes) not in (3, 4)):
        reject()
    found = {}
    for entry in changes:
        if not isinstance(entry, dict) or entry.get("Type") != "Resource":
            reject()
        resource = entry.get("ResourceChange")
        if not isinstance(resource, dict):
            reject()
        logical = resource.get("LogicalResourceId")
        if logical in found:
            reject()
        found[logical] = resource
    if set(found) not in ({FUNCTION, ALIAS, new}, {FUNCTION, ALIAS, old, new}):
        reject()
    _modify(found[FUNCTION], FUNCTION, "AWS::Lambda::Function", "Code")
    _modify(found[ALIAS], ALIAS, "AWS::Lambda::Alias", "FunctionVersion")
    addition = found[new]
    if (addition.get("Action") != "Add" or addition.get("ResourceType") != "AWS::Lambda::Version"
            or addition.get("Replacement") not in (None, "False") or addition.get("Scope")
            or addition.get("ChangeSetId") or addition.get("ModuleInfo")):
        reject()
    if old in found:
        removal = found[old]
        if (removal.get("Action") != "Remove" or removal.get("ResourceType") != "AWS::Lambda::Version"
                or removal.get("PolicyAction") != "Retain" or removal.get("Replacement") not in (None, "False")
                or removal.get("Scope") or removal.get("ChangeSetId") or removal.get("ModuleInfo")):
            reject()


def package_code(build: Path, bucket: str, prefix: str) -> tuple[bytes, str, str]:
    """Zip only the manifest-verified authoring build with stable metadata."""
    directory = build / FUNCTION
    if not directory.is_dir() or directory.is_symlink():
        reject()
    entries = list(directory.rglob("*"))
    files = sorted(path for path in entries if path.is_file())
    if (not files or any(path.is_symlink() for path in entries)
            or any(not path.resolve().is_relative_to(directory.resolve()) for path in files)):
        reject()
    names = [path.relative_to(directory).as_posix() for path in files]
    if len(set(names)) != len(names) or "content_hub_v2_authoring_handler.py" not in names:
        reject()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path, name in zip(files, names):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = (0o100644 << 16)
            archive.writestr(entry, path.read_bytes())
    data = output.getvalue()
    digest = hashlib.sha256(data).digest()
    key = f"{prefix}/authoring-{digest.hex()}.zip"
    return data, key, base64.b64encode(digest).decode("ascii")


def verify_artifact_identity(build: Path, env: dict) -> None:
    """Bind the selected source and exact verified manifest to this runner."""
    expected = {"schema": "zoolanding-thn-test-release/v1", "service": "zoolanding-content-hub",
                "source_sha": env["GITHUB_SHA"], "run_id": env["GITHUB_RUN_ID"],
                "run_attempt": env["GITHUB_RUN_ATTEMPT"]}
    try:
        metadata = json.loads((build / "release-metadata.json").read_text(encoding="utf-8"))
        manifest = (build.parent / "build-manifest.sha256").read_bytes()
    except (OSError, ValueError, TypeError):
        reject()
    if (metadata != expected or not re.fullmatch(r"[a-f0-9]{64}", env.get("EXPECTED_MANIFEST_DIGEST", ""))
            or hashlib.sha256(manifest).hexdigest() != env["EXPECTED_MANIFEST_DIGEST"]):
        reject()


def _snapshot(session, cfn, account: str) -> dict:
    stack = cfn.describe_stacks(StackName=release.STACK)["Stacks"][0]
    release.validate_stack(stack, account)
    if stack["StackStatus"] != "UPDATE_COMPLETE" or release._parameters(stack).get(release.ENABLE) != "true":
        reject()
    stack_id = stack["StackId"]
    original = release._load_template(cfn.get_template(StackName=stack_id, TemplateStage="Original")["TemplateBody"])
    processed = release._load_template(cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"])
    inventory = release._inventory(cfn, stack_id)
    release.verify_shared_base(inventory)
    release.verify_runtime(session, inventory, processed, account)
    release._verify_retained_state(session, inventory, processed, account)
    versions = _version_ids(processed["Resources"])
    if len(versions) != 1 or not _version_reference(processed["Resources"][ALIAS]["Properties"]["FunctionVersion"], next(iter(versions))):
        reject()
    if (inventory.get(FUNCTION, {}).get("ResourceType") != "AWS::Lambda::Function"
            or inventory.get(ALIAS, {}).get("ResourceType") != "AWS::Lambda::Alias"
            or inventory.get(next(iter(versions)), {}).get("ResourceType") != "AWS::Lambda::Version"):
        reject()
    function_name = inventory[FUNCTION]["PhysicalResourceId"]
    client = session.client("lambda", region_name=release.REGION)
    alias = client.get_alias(FunctionName=function_name, Name="test")
    version = client.get_function_configuration(FunctionName=function_name, Qualifier=alias["FunctionVersion"])
    if version.get("Version") != alias["FunctionVersion"] or not version.get("CodeSha256"):
        reject()
    physical_version = inventory[next(iter(versions))]["PhysicalResourceId"]
    if not physical_version.endswith(":" + alias["FunctionVersion"]):
        reject()
    routes = release._routes(session, inventory)
    release._verify_routes(routes, routes, True)
    return {"stack": stack, "original": original, "processed": processed, "inventory": inventory,
            "routes": routes, "alias": alias, "version": version}


def _same_before(a: dict, b: dict) -> bool:
    stable = ("stack", "original", "processed", "inventory", "routes")
    if any(a[key] != b[key] for key in stable):
        return False
    for key in ("alias", "version"):
        before = {name: value for name, value in a[key].items() if name != "ResponseMetadata"}
        after = {name: value for name, value in b[key].items() if name != "ResponseMetadata"}
        if before != after:
            return False
    return True


def rollback_record(before: dict, old_version: str, new_code_uri: str, source_sha: str) -> dict:
    """Keep private coordinates for a separately reviewed recovery."""
    try:
        return {"schema": "zoolanding-thn-authoring-rollback/v1", "source_sha": source_sha,
                "previous_code_uri": before["original"]["Resources"][FUNCTION]["Properties"]["CodeUri"],
                "previous_version_logical_id": old_version,
                "previous_version_physical_id": before["inventory"][old_version]["PhysicalResourceId"],
                "previous_alias_version": before["alias"]["FunctionVersion"],
                "previous_code_sha256": before["version"]["CodeSha256"],
                "new_code_uri": new_code_uri}
    except (KeyError, TypeError, AttributeError):
        reject()


def run(session, env: dict, operation: str) -> dict:
    release.validate_context(env)
    bucket = env.get("ARTIFACTS_BUCKET", "")
    if (operation not in ("verify", "apply") or env.get("GITHUB_ACTIONS") != "true"
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket)):
        reject()
    build = _ROOT.parent
    verify_artifact_identity(build, env)
    identity = session.client("sts", region_name=release.REGION).get_caller_identity()
    release.validate_deploy_identity(identity)
    account = identity["Account"]
    cfn = session.client("cloudformation", region_name=release.REGION)
    before = _snapshot(session, cfn, account)
    stack_id = before["stack"]["StackId"]
    params_before = release._parameters(before["stack"])
    params = [{"ParameterKey": key, "UsePreviousValue": True} for key in sorted(params_before)]
    if release.effective_parameters(before["original"], params_before, params) != params_before:
        reject()
    prefix = f"{release.STACK}/thn/authoring/{env['GITHUB_RUN_ID']}/{env['GITHUB_RUN_ATTEMPT']}/{env['GITHUB_SHA']}"
    package, code_key, code_sha = package_code(build, bucket, prefix)
    code_uri = f"s3://{bucket}/{code_key}"
    composed = compose_template(before["original"], code_uri)
    if operation == "verify":
        return {"operation": "verify", "decision": "ready", "source_sha": env["GITHUB_SHA"]}
    s3 = session.client("s3", region_name=release.REGION)
    s3.put_object(Bucket=bucket, Key=code_key, Body=package, ContentType="application/zip",
                  ServerSideEncryption="AES256", ExpectedBucketOwner=account)
    serialized = json.dumps(composed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(serialized).hexdigest()
    template_key = f"{prefix}/template-{digest}.json"
    s3.put_object(Bucket=bucket, Key=template_key, Body=serialized, ContentType="application/json",
                  ServerSideEncryption="AES256", ExpectedBucketOwner=account)
    name = f"thn-authoring-{env['GITHUB_RUN_ID']}-{env['GITHUB_RUN_ATTEMPT']}"
    created = cfn.create_change_set(StackName=stack_id, ChangeSetName=name, ChangeSetType="UPDATE",
        IncludeNestedStacks=False, TemplateURL=f"https://s3.{release.REGION}.amazonaws.com/{bucket}/{template_key}",
        Parameters=params, Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Description=f"THN TEST authoring code source {env['GITHUB_SHA']}", ClientToken=name)
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
            raise PatchBlocked("thn_authoring_change_set_timeout")
        if plan.get("Status") == "FAILED":
            retain_failed = True
            raise PatchBlocked("thn_authoring_change_set_failed_diagnostic_retained")
        if (plan.get("ChangeSetId") != change_id or plan.get("StackId") != stack_id
                or plan.get("StackName") != release.STACK or plan.get("ChangeSetName") != name
                or plan.get("Status") != "CREATE_COMPLETE" or plan.get("ExecutionStatus") != "AVAILABLE"
                or plan.get("NextToken") or release.ordinary_review._parameter_map(plan.get("Parameters")) != params_before):
            reject()
        plan_original = release._load_template(cfn.get_template(StackName=stack_id, ChangeSetName=change_id,
                                                                TemplateStage="Original")["TemplateBody"])
        plan_processed = release._load_template(cfn.get_template(StackName=stack_id, ChangeSetName=change_id,
                                                                 TemplateStage="Processed")["TemplateBody"])
        if plan_original != composed:
            reject()
        old_version, new_version = review_processed(before["processed"], plan_processed)
        if plan_processed["Resources"][FUNCTION]["Properties"]["Code"] != {"S3Bucket": bucket, "S3Key": code_key}:
            reject()
        review_changes(plan.get("Changes"), old_version, new_version)
        if not _same_before(before, _snapshot(session, cfn, account)):
            reject()
        rollback = json.dumps(rollback_record(before, old_version, code_uri, env["GITHUB_SHA"]),
                              sort_keys=True, separators=(",", ":")).encode("utf-8")
        rollback_key = f"{prefix}/rollback-{hashlib.sha256(rollback).hexdigest()}.json"
        s3.put_object(Bucket=bucket, Key=rollback_key, Body=rollback, ContentType="application/json",
                      ServerSideEncryption="AES256", ExpectedBucketOwner=account)
        cfn.execute_change_set(StackName=stack_id, ChangeSetName=change_id, ClientRequestToken=name)
        executed = True
        cfn.get_waiter("stack_update_complete").wait(StackName=stack_id, WaiterConfig={"Delay": 10, "MaxAttempts": 180})
        final = _snapshot(session, cfn, account)
        final_inventory = final["inventory"]
        expected_inventory = deepcopy(before["inventory"])
        expected_inventory.pop(old_version)
        expected_inventory[new_version] = final_inventory.get(new_version)
        current_alias = final["alias"]
        current_version = final["version"]
        if (final["stack"]["StackId"] != stack_id or release._parameters(final["stack"]) != params_before
                or final["original"] != composed or final["processed"] != plan_processed
                or final_inventory != expected_inventory or final["routes"] != before["routes"]
                or current_alias.get("RoutingConfig", {}).get("AdditionalVersionWeights")
                or current_alias.get("FunctionVersion") == before["alias"].get("FunctionVersion")
                or current_version.get("CodeSha256") != code_sha):
            reject()
        previous = session.client("lambda", region_name=release.REGION).get_function_configuration(
            FunctionName=before["inventory"][FUNCTION]["PhysicalResourceId"],
            Qualifier=before["alias"]["FunctionVersion"])
        if (previous.get("Version") != before["version"].get("Version")
                or previous.get("CodeSha256") != before["version"].get("CodeSha256")):
            reject()
        return {"operation": "apply", "decision": "executed", "source_sha": env["GITHUB_SHA"],
                "template_sha256": digest, "retained_previous_version": old_version}
    finally:
        if not executed and not retain_failed:
            cfn.delete_change_set(StackName=stack_id, ChangeSetName=change_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation", choices=["verify", "apply"], required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run(boto3.Session(region_name=release.REGION), dict(os.environ), args.operation), sort_keys=True))
        return 0
    except PatchBlocked as error:
        print(str(error), file=sys.stderr)
    except release.ReleaseBlocked:
        print("thn_authoring_patch_release_guard_failed", file=sys.stderr)
    except Exception:
        print("thn_authoring_patch_release_failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
