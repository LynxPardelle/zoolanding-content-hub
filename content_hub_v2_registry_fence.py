"""Atomic writer-epoch fence for final THN Content Hub v2 mutations."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping, Sequence

from service_binding_registry_consumer_v2 import (
    APPROVED_PARTITION_KEY,
    APPROVED_SORT_KEY,
    APPROVED_TABLE_NAME,
    RegistryConsumerError,
    load_active_service_binding,
    marshal_item,
    unmarshal_item,
)


_ALLOWED_WRITER_MODES = frozenset({"qa-only", "client-owner"})
_ALLOWED_MUTATION_OPERATIONS = frozenset({"Put", "Update", "Delete"})
_FENCED_FIELDS = (
    "recordType",
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
    "reservationOwner",
)


class RegistryFenceError(RuntimeError):
    """A final v2 mutation cannot safely use the current registry state."""


def _reject_binding() -> None:
    raise RegistryFenceError("service binding is unavailable")


def _reject_commit() -> None:
    raise RegistryFenceError("service binding changed before commit")


def _validated_mutation_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _reject_binding()
    if not 1 <= len(value) <= 99:
        _reject_binding()

    items: list[dict[str, Any]] = []
    for candidate in value:
        if not isinstance(candidate, Mapping) or len(candidate) != 1:
            _reject_binding()
        operation = next(iter(candidate), None)
        if operation not in _ALLOWED_MUTATION_OPERATIONS:
            _reject_binding()
        body = candidate.get(operation)
        if not isinstance(body, Mapping) or not isinstance(body.get("TableName"), str):
            _reject_binding()
        table_name = body["TableName"]
        if not table_name or table_name == APPROVED_TABLE_NAME:
            _reject_binding()
        items.append(deepcopy(dict(candidate)))
    return items


def _condition_check(record: Mapping[str, Any]) -> dict[str, Any]:
    names = {f"#{field}": field for field in _FENCED_FIELDS}
    values = {
        f":{field}": marshal_item({"value": record[field]})["value"]
        for field in _FENCED_FIELDS
    }
    expression = " AND ".join(f"#{field} = :{field}" for field in _FENCED_FIELDS)
    return {
        "ConditionCheck": {
            "TableName": APPROVED_TABLE_NAME,
            "Key": marshal_item({"pk": APPROVED_PARTITION_KEY, "sk": APPROVED_SORT_KEY}),
            "ConditionExpression": expression,
            "ExpressionAttributeNames": names,
            "ExpressionAttributeValues": values,
        }
    }


def execute_registry_fenced_transaction(
    dynamodb_client: Any,
    *,
    mutation_items: Sequence[Mapping[str, Any]],
    expected_descriptor: Mapping[str, Any],
    expected_registry_revision: int,
    expected_writer_mode: str,
    trusted_resource_scope: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Commit up to 99 non-registry mutations behind the current exact epoch.

    The strongly consistent read authorizes request preparation. The first
    operation in the final DynamoDB transaction independently checks the full
    authoritative row, so disabling writers or changing any binding coordinate
    between read and commit cancels the entire transaction.
    """

    items = _validated_mutation_items(mutation_items)
    if expected_writer_mode not in _ALLOWED_WRITER_MODES:
        _reject_binding()
    try:
        record = load_active_service_binding(
            dynamodb_client,
            expected_descriptor=expected_descriptor,
            expected_registry_revision=expected_registry_revision,
            trusted_resource_scope=trusted_resource_scope,
        )
    except RegistryConsumerError:
        _reject_binding()

    if record.get("writerMode") != expected_writer_mode:
        _reject_binding()

    try:
        return dynamodb_client.transact_write_items(
            TransactItems=[_condition_check(record), *items],
        )
    except Exception:
        _reject_commit()


__all__ = [
    "APPROVED_TABLE_NAME",
    "RegistryFenceError",
    "execute_registry_fenced_transaction",
    "marshal_item",
    "unmarshal_item",
]
