"""Fail-closed exact-key reader for the private THN Content Hub v2 registry."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Mapping

import service_binding_registry_v2 as registry
from service_binding_registry_operator_lambda import marshal_item, unmarshal_item


APPROVED_TABLE_NAME = "zoolanding-content-hub-test-ServiceBindingRegistryV2"
APPROVED_PARTITION_KEY = "SERVICE_BINDING#test#thn-journal-test-v2"
APPROVED_SORT_KEY = "REGISTRY#V2"

_EXPECTED_DESCRIPTOR_FIELDS = frozenset(
    {"descriptorVersionId", "descriptorSha256", "authPolicyVersion"}
)
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]+$")


class RegistryConsumerError(RuntimeError):
    """The authoritative binding cannot safely authorize a v2 consumer."""


def _reject() -> None:
    raise RegistryConsumerError("service binding is unavailable")


def _validate_expected_descriptor(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _EXPECTED_DESCRIPTOR_FIELDS:
        _reject()
    descriptor_version = value.get("descriptorVersionId")
    descriptor_sha256 = value.get("descriptorSha256")
    auth_policy_version = value.get("authPolicyVersion")
    if (
        not isinstance(descriptor_version, str)
        or not _SAFE_ID_RE.fullmatch(descriptor_version)
        or not isinstance(descriptor_sha256, str)
        or not _SHA256_RE.fullmatch(descriptor_sha256)
        or not isinstance(auth_policy_version, str)
        or not _SAFE_ID_RE.fullmatch(auth_policy_version)
    ):
        _reject()
    return {
        "descriptorVersionId": descriptor_version,
        "descriptorSha256": descriptor_sha256,
        "authPolicyVersion": auth_policy_version,
    }


def _validate_trusted_resource_scope(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"partition", "accountId", "region"}:
        _reject()
    partition = value.get("partition")
    account_id = value.get("accountId")
    region = value.get("region")
    if (
        partition not in {"aws", "aws-us-gov", "aws-cn"}
        or not isinstance(account_id, str)
        or not _ACCOUNT_ID_RE.fullmatch(account_id)
        or not isinstance(region, str)
        or not _REGION_RE.fullmatch(region)
    ):
        _reject()
    return {"partition": partition, "accountId": account_id, "region": region}


def load_active_service_binding(
    dynamodb_client: Any,
    *,
    expected_descriptor: Mapping[str, Any],
    expected_registry_revision: int,
    trusted_resource_scope: Mapping[str, Any],
) -> dict[str, Any]:
    """Load and revalidate the one active registry row.

    Callers provide descriptor coordinates from their server-owned immutable
    configuration, never from a browser request. The table and key are fixed
    here so the consumer cannot be redirected to another binding.
    """

    expected = _validate_expected_descriptor(expected_descriptor)
    if type(expected_registry_revision) is not int or expected_registry_revision < 1:
        _reject()
    scope = _validate_trusted_resource_scope(trusted_resource_scope)
    try:
        response = dynamodb_client.get_item(
            TableName=APPROVED_TABLE_NAME,
            Key=marshal_item({"pk": APPROVED_PARTITION_KEY, "sk": APPROVED_SORT_KEY}),
            ConsistentRead=True,
        )
        raw_item = response.get("Item") if isinstance(response, Mapping) else None
        if not isinstance(raw_item, Mapping) or not raw_item:
            _reject()
        item = unmarshal_item(raw_item)
        definition = {field: item[field] for field in registry.DEFINITION_FIELDS}
        rebuilt = registry.build_registry_record(
            definition,
            trusted_resource_scope=scope,
        )
        if item != rebuilt or item.get("activationStatus") != "active":
            _reject()
        if item.get("registryRevision") != expected_registry_revision:
            _reject()
        if any(item.get(field) != value for field, value in expected.items()):
            _reject()
        return deepcopy(rebuilt)
    except RegistryConsumerError:
        raise
    except Exception:
        _reject()


__all__ = [
    "APPROVED_TABLE_NAME",
    "RegistryConsumerError",
    "load_active_service_binding",
    "marshal_item",
    "unmarshal_item",
]
