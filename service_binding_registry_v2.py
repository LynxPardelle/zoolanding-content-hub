"""Authoritative private service-binding registry contract for Content Hub v2.

This module intentionally has no HTTP handler.  Runtime consumers are added by
later workstreams; TASK-008 only defines and conditionally operates the private
registry record.
"""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Mapping
from urllib.parse import urlparse


SCHEMA_VERSION = 2
RECORD_TYPE = "service-binding-registry-v2"
RECORD_SORT_KEY = "REGISTRY#V2"
ALLOWED_ACTIVATION_STATUSES = frozenset({"inactive", "active"})
ALLOWED_WRITER_MODES = frozenset({"disabled", "qa-only", "client-owner"})
APPROVED_ENVIRONMENT = "test"
APPROVED_DOMAIN = "thehairnarrative.com"
APPROVED_SERVICE_BINDING_ID = "thn-journal-test-v2"
APPROVED_HUB_ID = "thehairnarrative-com-journal"
APPROVED_AUTH_PROFILE_ID = "journal-owner"
APPROVED_ADMIN_ORIGIN = "https://admin-test.thehairnarrative.com"
APPROVED_COOKIE_NAMESPACE = "endefiz7dkk635k6di6k"
# Code-owned server scope from Config Authoring. It is never accepted from a
# CLI flag or inferred from the proposed registry record.
TRUSTED_TENANT_ID = "thehairnarrative-com"

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DOMAIN_RE = re.compile(r"^(?!-)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]+$")
_ARN_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):([a-z0-9-]+):([a-z0-9-]+):([0-9]{12}):(.+)$"
)

# TASK-008 reserves these exact future THN v2 resources. TASK-019 must create
# them with these physical names before activation and can expand this
# allowlist only through a separately reviewed contract change.
RESOURCE_BINDING_SPECS = {
    "authoringFunctionArn": (
        "lambda",
        "function:zoolanding-content-hub-test-ThnContentHubV2Authoring",
    ),
    "metadataTableArn": (
        "dynamodb",
        "table/zoolanding-content-hub-test-ThnContentHubV2Metadata",
    ),
}

DEFINITION_FIELDS = frozenset(
    {
        "schemaVersion",
        "environment",
        "domain",
        "serviceBindingId",
        "descriptorVersionId",
        "descriptorSha256",
        "registryRevision",
        "activationStatus",
        "writerMode",
        "writerEpoch",
        "hubId",
        "tenantId",
        "cookieNamespace",
        "authProfileId",
        "authPolicyVersion",
        "adminOrigin",
        "resourceBindings",
    }
)


class RegistryValidationError(ValueError):
    """The proposed private registry record is malformed or unsafe."""


class RegistryConflictError(RuntimeError):
    """A binding or hub reservation already belongs to another definition."""


class RegistryConditionalWriteFailed(RuntimeError):
    """The storage adapter rejected a conditional write."""


def _require_safe_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
        raise RegistryValidationError(f"{field} must be a safe identifier")
    return value


def _require_positive_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RegistryValidationError(f"{field} must be a positive integer")
    return value


def _validate_origin(value: Any, domain: str) -> str:
    if not isinstance(value, str):
        raise RegistryValidationError("adminOrigin must be an HTTPS origin")
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise RegistryValidationError("adminOrigin contains an invalid port") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise RegistryValidationError("adminOrigin must be an HTTPS origin without path, query, or fragment")
    host = parsed.hostname.lower()
    if host == domain or not host.endswith(f".{domain}"):
        raise RegistryValidationError("adminOrigin must be a dedicated subdomain of domain")
    return f"https://{host}"


def _validate_trusted_resource_scope(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"partition", "accountId", "region"}:
        raise RegistryValidationError("trusted resource scope is invalid")
    partition = value.get("partition")
    account_id = value.get("accountId")
    region = value.get("region")
    if partition not in {"aws", "aws-us-gov", "aws-cn"}:
        raise RegistryValidationError("trusted resource scope is invalid")
    if not isinstance(account_id, str) or not _ACCOUNT_ID_RE.fullmatch(account_id):
        raise RegistryValidationError("trusted resource scope is invalid")
    if not isinstance(region, str) or not _REGION_RE.fullmatch(region):
        raise RegistryValidationError("trusted resource scope is invalid")
    return {"partition": partition, "accountId": account_id, "region": region}


def _validate_resource_bindings(value: Any, trusted_scope: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != set(RESOURCE_BINDING_SPECS):
        raise RegistryValidationError("resourceBindings must match the approved TASK-008 allowlist")
    bindings: dict[str, str] = {}
    for key, resource_arn in value.items():
        if (
            not isinstance(resource_arn, str)
            or len(resource_arn) > 512
            or "*" in resource_arn
            or "?" in resource_arn
            or any(character.isspace() for character in resource_arn)
        ):
            raise RegistryValidationError("resourceBindings contains an invalid ARN")
        arn_match = _ARN_RE.fullmatch(resource_arn)
        if not arn_match:
            raise RegistryValidationError("resourceBindings contains an invalid ARN")
        partition, service, region, account_id, resource = arn_match.groups()
        expected_service, expected_resource = RESOURCE_BINDING_SPECS[key]
        if (
            service != expected_service
            or partition != trusted_scope["partition"]
            or region != trusted_scope["region"]
            or account_id != trusted_scope["accountId"]
            or resource != expected_resource
        ):
            raise RegistryValidationError("resourceBindings does not match the trusted resource scope")
        bindings[key] = resource_arn
    return dict(sorted(bindings.items()))


def build_registry_record(
    definition: Mapping[str, Any],
    *,
    trusted_resource_scope: Mapping[str, str],
) -> dict[str, Any]:
    """Validate an exact private definition and derive its authoritative row."""

    trusted_scope = _validate_trusted_resource_scope(trusted_resource_scope)
    if not isinstance(definition, Mapping):
        raise RegistryValidationError("registry definition must be an object")
    fields = set(definition)
    if fields != DEFINITION_FIELDS:
        missing_count = len(DEFINITION_FIELDS - fields)
        unknown_count = len(fields - DEFINITION_FIELDS)
        raise RegistryValidationError(
            f"registry definition fields mismatch; missingCount={missing_count}; unknownCount={unknown_count}"
        )
    if type(definition["schemaVersion"]) is not int or definition["schemaVersion"] != SCHEMA_VERSION:
        raise RegistryValidationError("schemaVersion must be 2")

    environment = _require_safe_id(definition["environment"], "environment")
    if environment != APPROVED_ENVIRONMENT:
        raise RegistryValidationError("environment does not match the approved TASK-008 binding")
    domain = definition["domain"]
    if not isinstance(domain, str) or domain != domain.lower() or not _DOMAIN_RE.fullmatch(domain):
        raise RegistryValidationError("domain must be a canonical lowercase domain")
    if domain != APPROVED_DOMAIN:
        raise RegistryValidationError("domain does not match the approved TASK-008 binding")

    service_binding_id = _require_safe_id(definition["serviceBindingId"], "serviceBindingId")
    if service_binding_id != APPROVED_SERVICE_BINDING_ID:
        raise RegistryValidationError("serviceBindingId does not match the approved TASK-008 binding")
    descriptor_version_id = _require_safe_id(definition["descriptorVersionId"], "descriptorVersionId")
    descriptor_sha256 = definition["descriptorSha256"]
    if not isinstance(descriptor_sha256, str) or not _SHA256_RE.fullmatch(descriptor_sha256):
        raise RegistryValidationError("descriptorSha256 must be a lowercase SHA-256 hex digest")

    registry_revision = _require_positive_integer(definition["registryRevision"], "registryRevision")
    writer_epoch = _require_positive_integer(definition["writerEpoch"], "writerEpoch")
    activation_status = definition["activationStatus"]
    if not isinstance(activation_status, str) or activation_status not in ALLOWED_ACTIVATION_STATUSES:
        raise RegistryValidationError("activationStatus is invalid")
    writer_mode = definition["writerMode"]
    if not isinstance(writer_mode, str) or writer_mode not in ALLOWED_WRITER_MODES:
        raise RegistryValidationError("writerMode is invalid")

    hub_id = _require_safe_id(definition["hubId"], "hubId")
    if hub_id != APPROVED_HUB_ID:
        raise RegistryValidationError("hubId does not match the approved TASK-008 binding")
    tenant_id = _require_safe_id(definition["tenantId"], "tenantId")
    if tenant_id != TRUSTED_TENANT_ID:
        raise RegistryValidationError("tenantId does not match the code-owned server scope")
    cookie_namespace = _require_safe_id(definition["cookieNamespace"], "cookieNamespace")
    if cookie_namespace != APPROVED_COOKIE_NAMESPACE:
        raise RegistryValidationError("cookieNamespace does not match the approved SEC-001 derivation")
    auth_profile_id = _require_safe_id(definition["authProfileId"], "authProfileId")
    if auth_profile_id != APPROVED_AUTH_PROFILE_ID:
        raise RegistryValidationError("authProfileId does not match the approved TASK-008 binding")
    auth_policy_version = _require_safe_id(definition["authPolicyVersion"], "authPolicyVersion")
    if definition["adminOrigin"] != APPROVED_ADMIN_ORIGIN:
        raise RegistryValidationError("adminOrigin does not match the approved TASK-008 binding")
    admin_origin = _validate_origin(definition["adminOrigin"], domain)
    resource_bindings = _validate_resource_bindings(definition["resourceBindings"], trusted_scope)

    owner = {
        "environment": environment,
        "domain": domain,
        "serviceBindingId": service_binding_id,
        "hubId": hub_id,
        "tenantId": tenant_id,
        "authProfileId": auth_profile_id,
    }
    return {
        "pk": f"SERVICE_BINDING#{environment}#{service_binding_id}",
        "sk": RECORD_SORT_KEY,
        "recordType": RECORD_TYPE,
        "schemaVersion": SCHEMA_VERSION,
        "environment": environment,
        "domain": domain,
        "serviceBindingId": service_binding_id,
        "descriptorVersionId": descriptor_version_id,
        "descriptorSha256": descriptor_sha256,
        "registryRevision": registry_revision,
        "activationStatus": activation_status,
        "writerMode": writer_mode,
        "writerEpoch": writer_epoch,
        "hubId": hub_id,
        "tenantId": tenant_id,
        "cookieNamespace": cookie_namespace,
        "authProfileId": auth_profile_id,
        "authPolicyVersion": auth_policy_version,
        "adminOrigin": admin_origin,
        "resourceBindings": deepcopy(resource_bindings),
        "reservationOwner": owner,
    }


def binding_key(record: Mapping[str, Any]) -> dict[str, str]:
    return {"pk": str(record["pk"]), "sk": str(record["sk"])}


def reserve_service_binding(store: Any, definition: Mapping[str, Any]) -> dict[str, Any]:
    """Conditionally reserve one authoritative binding record.

    The adapter must implement strongly consistent exact-key reads plus one
    conditional create. A repeated exact request is idempotent; a conflicting
    owner or definition fails closed. Global hub reservation is TASK-012.
    """

    record = build_registry_record(
        definition,
        trusted_resource_scope=store.get_trusted_resource_scope(),
    )
    if record["activationStatus"] != "inactive":
        raise RegistryValidationError("an initial reservation must be inactive")
    if record["writerMode"] != "disabled":
        raise RegistryValidationError("an initial reservation must disable writers")
    if record["writerEpoch"] != 1:
        raise RegistryValidationError("an initial reservation must start at writerEpoch 1")
    if record["registryRevision"] != 1:
        raise RegistryValidationError("an initial reservation must start at registryRevision 1")

    current_binding = store.get_binding(binding_key(record))
    if current_binding:
        if dict(current_binding) == record:
            return {"created": False, "record": deepcopy(dict(current_binding))}
        raise RegistryConflictError("service binding is already reserved")

    try:
        store.create_binding(record)
    except RegistryConditionalWriteFailed as error:
        current_binding = store.get_binding(binding_key(record))
        if current_binding and dict(current_binding) == record:
            return {"created": False, "record": deepcopy(dict(current_binding))}
        raise RegistryConflictError("concurrent service binding reservation conflict") from error
    return {"created": True, "record": deepcopy(record)}


def update_service_binding(
    store: Any,
    definition: Mapping[str, Any],
    *,
    expected_registry_revision: int,
    expected_writer_epoch: int,
) -> dict[str, Any]:
    """Conditionally replace a registry row while preserving its reservation.

    Registry revisions always advance by one.  The writer epoch advances by
    exactly one if and only if the private writer mode changes.
    """

    expected_registry_revision = _require_positive_integer(
        expected_registry_revision,
        "expected_registry_revision",
    )
    expected_writer_epoch = _require_positive_integer(
        expected_writer_epoch,
        "expected_writer_epoch",
    )
    desired = build_registry_record(
        definition,
        trusted_resource_scope=store.get_trusted_resource_scope(),
    )
    current = store.get_binding(binding_key(desired))
    if not current:
        raise RegistryConflictError("service binding reservation is missing")
    if (
        current.get("registryRevision") != expected_registry_revision
        or current.get("writerEpoch") != expected_writer_epoch
    ):
        raise RegistryConflictError("stale registry revision or writer epoch")
    if desired["reservationOwner"] != current.get("reservationOwner"):
        raise RegistryConflictError("reservation ownership is immutable")
    if desired["registryRevision"] != expected_registry_revision + 1:
        raise RegistryValidationError("registryRevision must increment exactly once")

    writer_mode_changed = desired["writerMode"] != current.get("writerMode")
    required_epoch = expected_writer_epoch + 1 if writer_mode_changed else expected_writer_epoch
    if desired["writerEpoch"] != required_epoch:
        if writer_mode_changed:
            raise RegistryValidationError("writerMode transitions must increment writerEpoch exactly once")
        raise RegistryValidationError("writerEpoch cannot change without a writerMode transition")

    expected = {
        "registryRevision": expected_registry_revision,
        "writerEpoch": expected_writer_epoch,
        "environment": current["environment"],
        "domain": current["domain"],
        "serviceBindingId": current["serviceBindingId"],
        "hubId": current["hubId"],
        "tenantId": current["tenantId"],
        "authProfileId": current["authProfileId"],
    }
    try:
        store.replace_binding(desired, expected)
    except RegistryConditionalWriteFailed as error:
        raise RegistryConflictError("concurrent registry transition conflict") from error
    return deepcopy(desired)
