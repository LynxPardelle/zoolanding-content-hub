"""Closed exception for three THN paths inside the existing shared HTTP API."""

from copy import deepcopy
import re

API = "ContentHubApi"
CONDITION = "IsThnContentHubV2Enabled"
PATHS = ("/features/content-hub-v2/read", "/features/content-hub-v2/action",
         "/features/content-hub-v2/public-media/{articleId}/{locale}/{revisionId}/{assetId}/{variantId}")


class ApiBoundaryError(ValueError):
    pass


def _uncondition(node):
    if isinstance(node, dict):
        if "Fn::If" in node:
            value = node["Fn::If"]
            if (set(node) != {"Fn::If"} or not isinstance(value, list) or len(value) != 3
                    or value[0] != CONDITION or value[2] != {"Ref": "AWS::NoValue"}):
                raise ApiBoundaryError("thn_path_condition_invalid")
            return _uncondition(value[1])
        return {key: _uncondition(value) for key, value in node.items()}
    if isinstance(node, list):
        return [_uncondition(value) for value in node]
    return node


def normalize_path(path):
    if not isinstance(path, dict) or set(path) != {"Fn::If"}:
        raise ApiBoundaryError("thn_path_must_be_enable_conditional")
    return _uncondition(path)


def _expected_path(path):
    public = path == PATHS[2]
    function = "ThnContentHubV2PublicMediaFunction" if public else "ThnContentHubV2AuthoringFunction"
    method = {"x-amazon-apigateway-integration": {"httpMethod": "POST", "type": "aws_proxy",
        "uri": {"Fn::Sub": "arn:${AWS::Partition}:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${" + function + "Aliastest}/invocations"},
        "payloadFormatVersion": "2.0"}, "responses": {}}
    if public:
        method["parameters"] = [{"required": True, "name": name, "in": "path"}
                                for name in ("articleId", "locale", "revisionId", "assetId", "variantId")]
    return {"get" if public else "post": method}


def _check_paths(body, *, require_all):
    if not isinstance(body, dict) or not isinstance(body.get("paths"), dict):
        raise ApiBoundaryError("api_body_missing")
    for path in PATHS:
        if path not in body["paths"]:
            if require_all:
                raise ApiBoundaryError("required_thn_path_missing")
        elif normalize_path(body["paths"][path]) != _expected_path(path):
            raise ApiBoundaryError("thn_path_contract_changed")


def _api(template):
    if not isinstance(template, dict):
        raise ApiBoundaryError("verified_template_snapshot_required")
    resource = template.get("Resources", {}).get(API)
    if not isinstance(resource, dict) or resource.get("Type") != "AWS::ApiGatewayV2::Api":
        raise ApiBoundaryError("verified_processed_api_required")
    return deepcopy(resource)


def compose_body(candidate, live_processed):
    """Copy every live non-THN field, then install only the exact candidate paths."""
    live_body = _api(live_processed).get("Properties", {}).get("Body")
    _check_paths(live_body, require_all=False)
    try:
        supplied = candidate["Resources"][API]["Properties"]["DefinitionBody"]
    except (KeyError, TypeError):
        raise ApiBoundaryError("candidate_definition_body_required") from None
    _check_paths(supplied, require_all=True)
    if {key: value for key, value in supplied.items() if key != "paths"} != {
            "openapi": "3.0.1", "info": {"title": {"Ref": "AWS::StackName"}, "version": "1.0"}}:
        raise ApiBoundaryError("candidate_body_global_field_not_allowlisted")
    if set(supplied["paths"]) != set(PATHS):
        raise ApiBoundaryError("candidate_path_set_not_exact")
    result = deepcopy(live_body)
    for path in PATHS:
        result["paths"][path] = deepcopy(supplied["paths"][path])
    return result


def verify_route_permissions(template):
    resources = template.get("Resources", {}) if isinstance(template, dict) else {}
    names = ("ThnContentHubV2AuthoringFunctionReadPermission", "ThnContentHubV2AuthoringFunctionActionPermission", "ThnContentHubV2PublicMediaFunctionPublicMediaPermission")
    for path, logical in zip(PATHS, names):
        public = path == PATHS[2]
        function = "ThnContentHubV2PublicMediaFunction" if public else "ThnContentHubV2AuthoringFunction"
        source_path = re.sub(r"\{[^}]+\}", "*", path)
        expected = {"Type": "AWS::Lambda::Permission", "Condition": CONDITION, "Properties": {
            "Action": "lambda:InvokeFunction", "FunctionName": {"Ref": function + "Aliastest"},
            "Principal": "apigateway.amazonaws.com", "SourceArn": {"Fn::Sub": [
                "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${__ApiId__}/${__Stage__}/" + ("GET" if public else "POST") + source_path,
                {"__ApiId__": {"Ref": API}, "__Stage__": "*"}]}}}
        if resources.get(logical) != expected:
            raise ApiBoundaryError("exact_thn_http_permission_mismatch")


def review_shared_api(resource_change, live_processed, candidate_processed, inventory):
    """Never authorize Modify by logical ID alone: verify physical ID and full diff."""
    live, candidate = _api(live_processed), _api(candidate_processed)
    item = inventory.get(API, {}) if isinstance(inventory, dict) else {}
    physical = item.get("PhysicalResourceId")
    if (item.get("ResourceType") != "AWS::ApiGatewayV2::Api" or not isinstance(physical, str)
            or re.fullmatch(r"[a-z0-9]{10}", physical) is None
            or resource_change.get("LogicalResourceId") != API
            or resource_change.get("PhysicalResourceId") != physical
            or resource_change.get("ResourceType") != "AWS::ApiGatewayV2::Api"
            or resource_change.get("Action") != "Modify" or resource_change.get("Replacement") != "False"
            or resource_change.get("Scope") != ["Properties"]):
        raise ApiBoundaryError("shared_api_identity_or_scope_invalid")
    details = resource_change.get("Details")
    if not isinstance(details, list) or not details:
        raise ApiBoundaryError("shared_api_body_details_required")
    for detail in details:
        target = detail.get("Target", {}) if isinstance(detail, dict) else {}
        if (target.get("Attribute") != "Properties" or target.get("Name") != "Body"
                or target.get("RequiresRecreation") != "Never"):
            raise ApiBoundaryError("shared_api_nonbody_target_forbidden")
    before_body = live.get("Properties", {}).pop("Body", None)
    after_body = candidate.get("Properties", {}).pop("Body", None)
    if live != candidate:
        raise ApiBoundaryError("shared_api_nonbody_field_changed")
    _check_paths(before_body, require_all=False)
    _check_paths(after_body, require_all=True)
    for path in PATHS:
        before_body["paths"].pop(path, None)
        after_body["paths"].pop(path, None)
    if before_body != after_body:
        raise ApiBoundaryError("shared_api_v1_or_global_field_changed")
