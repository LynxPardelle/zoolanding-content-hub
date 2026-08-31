"""Private, non-HTTP mutation boundary for the exact THN TEST v2 registry."""

from __future__ import annotations

import json
import re
from typing import Any, Mapping

import service_binding_registry_v2 as registry


APPROVED_TABLE_NAME = "zoolanding-content-hub-test-ServiceBindingRegistryV2"
APPROVED_PARTITION_KEY = "SERVICE_BINDING#test#thn-journal-test-v2"
APPROVED_SORT_KEY = "REGISTRY#V2"
_APPROVED_TABLE_ARN_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):dynamodb:([a-z0-9-]+):([0-9]{12}):"
    r"table/zoolanding-content-hub-test-ServiceBindingRegistryV2$"
)
_CONDITIONAL_ERROR_CODES = frozenset({"ConditionalCheckFailedException"})
_MAX_EVENT_BYTES = 256 * 1024
_EXPECTED_CONDITIONAL_FIELDS = frozenset(
    {
        "registryRevision",
        "writerEpoch",
        "environment",
        "domain",
        "serviceBindingId",
        "hubId",
        "tenantId",
        "authProfileId",
    }
)


class RegistryMutationInputError(ValueError):
    """The direct-invocation envelope is not the closed TASK-008 contract."""


class RegistryMutationServiceError(RuntimeError):
    """DynamoDB failed without exposing provider or record details."""


def marshal_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, int):
        return {"N": str(value)}
    if isinstance(value, Mapping):
        return {"M": {str(key): marshal_value(item) for key, item in value.items()}}
    if isinstance(value, (list, tuple)):
        return {"L": [marshal_value(item) for item in value]}
    raise RegistryMutationInputError("unsupported registry value type")


def marshal_item(item: Mapping[str, Any] | None) -> dict[str, Any]:
    if item is None:
        return {}
    return {str(key): marshal_value(value) for key, value in item.items()}


def unmarshal_value(value: Mapping[str, Any]) -> Any:
    if set(value) == {"S"}:
        return value["S"]
    if set(value) == {"N"}:
        number = str(value["N"])
        if not re.fullmatch(r"-?[0-9]+", number):
            raise RegistryMutationInputError("registry numeric values must be integers")
        return int(number)
    if set(value) == {"BOOL"}:
        return bool(value["BOOL"])
    if set(value) == {"M"} and isinstance(value["M"], Mapping):
        return {str(key): unmarshal_value(item) for key, item in value["M"].items()}
    if set(value) == {"L"} and isinstance(value["L"], list):
        return [unmarshal_value(item) for item in value["L"]]
    raise RegistryMutationInputError("unsupported DynamoDB registry value")


def unmarshal_item(item: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): unmarshal_value(value) for key, value in item.items()}


def _error_code(error: Exception) -> str:
    response = getattr(error, "response", None)
    if not isinstance(response, Mapping):
        return ""
    error_payload = response.get("Error")
    return str(error_payload.get("Code") or "") if isinstance(error_payload, Mapping) else ""


def _raise_registry_service_error(error: Exception) -> None:
    if _error_code(error) in _CONDITIONAL_ERROR_CODES:
        raise registry.RegistryConditionalWriteFailed() from None
    raise RegistryMutationServiceError("registry service request failed") from None


def _require_exact_binding_key(item: Mapping[str, Any], *, closed: bool = False) -> None:
    if closed and set(item) != {"pk", "sk"}:
        raise RegistryMutationInputError("registry key is invalid")
    if item.get("pk") != APPROVED_PARTITION_KEY or item.get("sk") != APPROVED_SORT_KEY:
        raise RegistryMutationInputError("registry key is invalid")


class DynamoDbRegistryStore:
    """Exact-table adapter exposed only inside the private mutation Lambda."""

    def __init__(self, client: Any):
        self._client = client

    def get_trusted_resource_scope(self) -> dict[str, str]:
        try:
            response = self._client.describe_table(TableName=APPROVED_TABLE_NAME)
        except Exception as error:
            _raise_registry_service_error(error)
        table = response.get("Table") if isinstance(response, Mapping) else None
        table_arn = table.get("TableArn") if isinstance(table, Mapping) else None
        match = _APPROVED_TABLE_ARN_RE.fullmatch(str(table_arn or ""))
        if not match:
            raise RegistryMutationServiceError("registry table identity is invalid")
        partition, region, account_id = match.groups()
        return {"partition": partition, "region": region, "accountId": account_id}

    def get_binding(self, key: Mapping[str, str]) -> dict[str, Any] | None:
        _require_exact_binding_key(key, closed=True)
        try:
            response = self._client.get_item(
                TableName=APPROVED_TABLE_NAME,
                Key=marshal_item(key),
                ConsistentRead=True,
            )
        except Exception as error:
            _raise_registry_service_error(error)
        item = response.get("Item") if isinstance(response, Mapping) else None
        return unmarshal_item(item) if isinstance(item, Mapping) and item else None

    def create_binding(self, binding: Mapping[str, Any]) -> None:
        _require_exact_binding_key(binding)
        try:
            self._client.put_item(
                TableName=APPROVED_TABLE_NAME,
                Item=marshal_item(binding),
                ConditionExpression="attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
                ExpressionAttributeNames={"#pk": "pk", "#sk": "sk"},
            )
        except Exception as error:
            _raise_registry_service_error(error)

    def replace_binding(self, binding: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
        _require_exact_binding_key(binding)
        if set(expected) != _EXPECTED_CONDITIONAL_FIELDS:
            raise RegistryMutationInputError("conditional registry fields are invalid")
        names = {"#pk": "pk", "#sk": "sk"}
        values: dict[str, Any] = {}
        conditions = ["attribute_exists(#pk)", "attribute_exists(#sk)"]
        for field in sorted(_EXPECTED_CONDITIONAL_FIELDS):
            names[f"#{field}"] = field
            values[f":{field}"] = marshal_value(expected[field])
            conditions.append(f"#{field} = :{field}")
        try:
            self._client.put_item(
                TableName=APPROVED_TABLE_NAME,
                Item=marshal_item(binding),
                ConditionExpression=" AND ".join(conditions),
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
            )
        except Exception as error:
            _raise_registry_service_error(error)


def _safe_summary(operation: str, record: Mapping[str, Any], *, created: bool | None = None) -> dict[str, Any]:
    summary = {
        "ok": True,
        "operation": operation,
        "environment": record["environment"],
        "domain": record["domain"],
        "serviceBindingId": record["serviceBindingId"],
        "descriptorVersionId": record["descriptorVersionId"],
        "registryRevision": record["registryRevision"],
    }
    if created is not None:
        summary["created"] = created
    return summary


def _validate_envelope(event: Any) -> tuple[str, Mapping[str, Any], int | None, int | None]:
    if not isinstance(event, Mapping):
        raise RegistryMutationInputError("registry request must be an object")
    try:
        encoded = json.dumps(event, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError):
        raise RegistryMutationInputError("registry request is invalid") from None
    if len(encoded) > _MAX_EVENT_BYTES:
        raise RegistryMutationInputError("registry request is too large")
    operation = event.get("operation")
    definition = event.get("definition")
    if operation == "reserve":
        if set(event) != {"operation", "definition"}:
            raise RegistryMutationInputError("reserve request fields are invalid")
        if not isinstance(definition, Mapping):
            raise RegistryMutationInputError("registry definition must be an object")
        return operation, definition, None, None
    if operation == "update":
        if set(event) != {
            "operation",
            "definition",
            "expectedRegistryRevision",
            "expectedWriterEpoch",
        }:
            raise RegistryMutationInputError("update request fields are invalid")
        if not isinstance(definition, Mapping):
            raise RegistryMutationInputError("registry definition must be an object")
        return (
            operation,
            definition,
            event["expectedRegistryRevision"],
            event["expectedWriterEpoch"],
        )
    raise RegistryMutationInputError("registry operation is invalid")


def handle_registry_request(event: Any, dynamodb_client: Any) -> dict[str, Any]:
    """Validate one closed request and execute the reviewed conditional operation."""

    try:
        operation, definition, expected_revision, expected_epoch = _validate_envelope(event)
        store = DynamoDbRegistryStore(dynamodb_client)
        if operation == "reserve":
            result = registry.reserve_service_binding(store, definition)
            return _safe_summary("reserve", result["record"], created=result["created"])
        record = registry.update_service_binding(
            store,
            definition,
            expected_registry_revision=expected_revision,
            expected_writer_epoch=expected_epoch,
        )
        return _safe_summary("update", record)
    except registry.RegistryConflictError:
        return {"ok": False, "error": "registry request conflict"}
    except (
        RegistryMutationInputError,
        registry.RegistryValidationError,
    ):
        return {"ok": False, "error": "registry request rejected"}
    except (RegistryMutationServiceError, registry.RegistryConditionalWriteFailed):
        return {"ok": False, "error": "registry service request failed"}
    except Exception:
        return {"ok": False, "error": "registry request failed"}


def lambda_handler(event: Any, _context: Any) -> dict[str, Any]:
    """AWS entry point; deliberately has no API Gateway or Function URL shape."""

    try:
        import boto3

        client = boto3.client("dynamodb")
    except Exception:
        return {"ok": False, "error": "registry service request failed"}
    return handle_registry_request(event, client)
