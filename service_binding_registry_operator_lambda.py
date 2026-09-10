"""Private, non-HTTP mutation and read-only inspection of the exact TEST registry."""

from __future__ import annotations

import json
import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Mapping

import service_binding_registry_v2 as registry


APPROVED_TABLE_NAME = "zoolanding-content-hub-test-ServiceBindingRegistryV2"
APPROVED_PARTITION_KEY = "SERVICE_BINDING#test#thn-journal-test-v2"
APPROVED_SORT_KEY = "REGISTRY#V2"
APPROVED_RESERVATION_PARTITION_KEY = "HUB_RESERVATION#thehairnarrative-com-journal"
APPROVED_RESERVATION_SORT_KEY = "GLOBAL"
APPROVED_AUDIT_PARTITION_KEY = "REGISTRY_AUDIT#test#thn-journal-test-v2"
_AUDIT_SORT_KEY_RE = re.compile(
    r"^EVENT#[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z#"
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
)
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
_EXPECTED_AUDIT_FIELDS = frozenset(
    {
        "pk",
        "sk",
        "recordType",
        "schemaVersion",
        "operation",
        "outcome",
        "occurredAt",
        "requestId",
        "registryRevision",
        "writerEpoch",
        "ownerDigest",
        "actorType",
    }
)
_AUDIT_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


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
    code = _error_code(error)
    if code in _CONDITIONAL_ERROR_CODES:
        raise registry.RegistryConditionalWriteFailed() from None
    if code == "TransactionCanceledException":
        response = getattr(error, "response", None)
        reasons = response.get("CancellationReasons") if isinstance(response, Mapping) else None
        if isinstance(reasons, list) and reasons:
            reason_codes = []
            for reason in reasons:
                if not isinstance(reason, Mapping) or not isinstance(reason.get("Code"), str):
                    break
                reason_codes.append(reason["Code"])
            else:
                if (
                    "ConditionalCheckFailed" in reason_codes
                    and set(reason_codes) <= {"None", "ConditionalCheckFailed"}
                ):
                    raise registry.RegistryConditionalWriteFailed() from None
    raise RegistryMutationServiceError("registry service request failed") from None


def _require_exact_binding_key(item: Mapping[str, Any], *, closed: bool = False) -> None:
    if closed and set(item) != {"pk", "sk"}:
        raise RegistryMutationInputError("registry key is invalid")
    if item.get("pk") != APPROVED_PARTITION_KEY or item.get("sk") != APPROVED_SORT_KEY:
        raise RegistryMutationInputError("registry key is invalid")


def _require_exact_reservation_key(
    item: Mapping[str, Any],
    *,
    closed: bool = False,
) -> None:
    if closed and set(item) != {"pk", "sk"}:
        raise RegistryMutationInputError("registry key is invalid")
    if (
        item.get("pk") != APPROVED_RESERVATION_PARTITION_KEY
        or item.get("sk") != APPROVED_RESERVATION_SORT_KEY
    ):
        raise RegistryMutationInputError("registry key is invalid")


def _require_exact_audit_key(item: Mapping[str, Any]) -> None:
    occurred_at = item.get("occurredAt")
    request_id = item.get("requestId")
    try:
        valid_occurred_at = isinstance(occurred_at, str) and datetime.strptime(
            occurred_at,
            "%Y-%m-%dT%H:%M:%S.%fZ",
        )
    except ValueError:
        valid_occurred_at = False
    operation_outcome = (item.get("operation"), item.get("outcome"))
    if (
        set(item) != _EXPECTED_AUDIT_FIELDS
        or item.get("pk") != APPROVED_AUDIT_PARTITION_KEY
        or not isinstance(item.get("sk"), str)
        or not _AUDIT_SORT_KEY_RE.fullmatch(item["sk"])
        or not valid_occurred_at
        or not isinstance(request_id, str)
        or not _AUDIT_REQUEST_ID_RE.fullmatch(request_id)
        or item["sk"] != f"EVENT#{occurred_at}#{request_id}"
        or item.get("recordType") != registry.AUDIT_RECORD_TYPE
        or item.get("schemaVersion") != registry.SCHEMA_VERSION
        or operation_outcome
        not in {("reserve", "created"), ("reserve", "idempotent"), ("update", "updated")}
        or isinstance(item.get("registryRevision"), bool)
        or not isinstance(item.get("registryRevision"), int)
        or item["registryRevision"] < 1
        or isinstance(item.get("writerEpoch"), bool)
        or not isinstance(item.get("writerEpoch"), int)
        or item["writerEpoch"] < 1
        or not isinstance(item.get("ownerDigest"), str)
        or not _SHA256_RE.fullmatch(item["ownerDigest"])
        or item.get("actorType") != "registry-operator"
    ):
        raise RegistryMutationInputError("registry audit key is invalid")


def _condition_check_for_exact_item(item: Mapping[str, Any]) -> dict[str, Any]:
    names = {"#pk": "pk", "#sk": "sk"}
    values: dict[str, Any] = {}
    conditions = ["attribute_exists(#pk)", "attribute_exists(#sk)"]
    for index, field in enumerate(sorted(set(item) - {"pk", "sk"})):
        name = f"#f{index}"
        value = f":v{index}"
        names[name] = field
        values[value] = marshal_value(item[field])
        conditions.append(f"{name} = {value}")
    return {
        "TableName": APPROVED_TABLE_NAME,
        "Key": marshal_item({"pk": item["pk"], "sk": item["sk"]}),
        "ConditionExpression": " AND ".join(conditions),
        "ExpressionAttributeNames": names,
        "ExpressionAttributeValues": values,
        "ReturnValuesOnConditionCheckFailure": "NONE",
    }


def _append_only_put(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "TableName": APPROVED_TABLE_NAME,
        "Item": marshal_item(item),
        "ConditionExpression": "attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
        "ExpressionAttributeNames": {"#pk": "pk", "#sk": "sk"},
        "ReturnValuesOnConditionCheckFailure": "NONE",
    }


def _transaction_token(audit: Mapping[str, Any]) -> str:
    material = "|".join(
        (
            str(audit.get("operation") or ""),
            str(audit.get("outcome") or ""),
            str(audit.get("requestId") or ""),
            str(audit.get("sk") or ""),
        )
    ).encode("utf-8")
    return f"thn-{hashlib.sha256(material).hexdigest()[:32]}"


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

    def get_global_reservation(self, key: Mapping[str, str]) -> dict[str, Any] | None:
        _require_exact_reservation_key(key, closed=True)
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

    def transact_create_binding(
        self,
        binding: Mapping[str, Any],
        reservation: Mapping[str, Any],
        audit: Mapping[str, Any],
    ) -> None:
        _require_exact_binding_key(binding)
        _require_exact_reservation_key(reservation)
        _require_exact_audit_key(audit)
        try:
            self._client.transact_write_items(
                TransactItems=[
                    {"Put": _append_only_put(reservation)},
                    {"Put": _append_only_put(binding)},
                    {"Put": _append_only_put(audit)},
                ],
                ClientRequestToken=_transaction_token(audit),
            )
        except Exception as error:
            _raise_registry_service_error(error)

    def transact_confirm_reservation(
        self,
        binding: Mapping[str, Any],
        reservation: Mapping[str, Any],
        audit: Mapping[str, Any],
    ) -> None:
        _require_exact_binding_key(binding)
        _require_exact_reservation_key(reservation)
        _require_exact_audit_key(audit)
        try:
            self._client.transact_write_items(
                TransactItems=[
                    {"ConditionCheck": _condition_check_for_exact_item(reservation)},
                    {"ConditionCheck": _condition_check_for_exact_item(binding)},
                    {"Put": _append_only_put(audit)},
                ],
                ClientRequestToken=_transaction_token(audit),
            )
        except Exception as error:
            _raise_registry_service_error(error)

    def transact_replace_binding(
        self,
        binding: Mapping[str, Any],
        reservation: Mapping[str, Any],
        expected: Mapping[str, Any],
        audit: Mapping[str, Any],
    ) -> None:
        _require_exact_binding_key(binding)
        _require_exact_reservation_key(reservation)
        _require_exact_audit_key(audit)
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
            self._client.transact_write_items(
                TransactItems=[
                    {"ConditionCheck": _condition_check_for_exact_item(reservation)},
                    {
                        "Put": {
                            "TableName": APPROVED_TABLE_NAME,
                            "Item": marshal_item(binding),
                            "ConditionExpression": " AND ".join(conditions),
                            "ExpressionAttributeNames": names,
                            "ExpressionAttributeValues": values,
                            "ReturnValuesOnConditionCheckFailure": "NONE",
                        }
                    },
                    {"Put": _append_only_put(audit)},
                ],
                ClientRequestToken=_transaction_token(audit),
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


def _inspect_registry(event: Mapping[str, Any], store: DynamoDbRegistryStore) -> dict[str, Any]:
    """Return a nonce-bound safe proof without repairing rows or writing audits.

    IAM authorization still covers this whole existing Lambda, not a payload
    operation. Inspection does not grant a caller an inspect-only IAM capability.
    """
    if (set(event) != {"operation", "nonce"} or not isinstance(event.get("nonce"), str)
            or re.fullmatch(r"[a-f0-9]{32}", event["nonce"]) is None):
        raise RegistryMutationInputError("inspection request fields are invalid")
    trusted_scope = store.get_trusted_resource_scope()
    key = {"pk": APPROVED_PARTITION_KEY, "sk": APPROVED_SORT_KEY}
    record = store.get_binding(key)
    if not isinstance(record, Mapping):
        raise RegistryMutationInputError("inspection registry is unavailable")
    definition = {field: record.get(field) for field in registry.DEFINITION_FIELDS}
    validated = registry.build_registry_record(definition, trusted_resource_scope=trusted_scope)
    if record != validated:
        raise RegistryMutationInputError("inspection registry is invalid")
    reservation = store.get_global_reservation(registry.global_reservation_key(validated))
    if reservation != registry.build_global_hub_reservation(validated):
        raise RegistryMutationInputError("inspection reservation is invalid")
    # A mutation between the two strong reads cannot yield a successful proof.
    if store.get_binding(key) != validated:
        raise RegistryMutationInputError("inspection registry changed")
    digest = hashlib.sha256(json.dumps({"binding": validated, "reservation": reservation},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()
    return {"ok": True, "operation": "inspect", "schemaVersion": 1, "nonce": event["nonce"],
            "scopeVerified": True, "bindingsVerified": True, "registrySha256": digest,
            **{field: validated[field] for field in ("descriptorVersionId", "descriptorSha256", "authPolicyVersion",
                "activationStatus", "writerMode", "writerEpoch", "registryRevision")}}


def handle_registry_request(
    event: Any,
    dynamodb_client: Any,
    *,
    audit_context: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate one closed request and execute the reviewed conditional operation."""

    try:
        if isinstance(event, Mapping) and event.get("operation") == "inspect":
            return _inspect_registry(event, DynamoDbRegistryStore(dynamodb_client))
        operation, definition, expected_revision, expected_epoch = _validate_envelope(event)
        store = DynamoDbRegistryStore(dynamodb_client)
        if operation == "reserve":
            result = registry.reserve_service_binding(
                store,
                definition,
                audit_context=audit_context,
            )
            return _safe_summary("reserve", result["record"], created=result["created"])
        record = registry.update_service_binding(
            store,
            definition,
            expected_registry_revision=expected_revision,
            expected_writer_epoch=expected_epoch,
            audit_context=audit_context,
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


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    """AWS entry point; deliberately has no API Gateway or Function URL shape."""

    try:
        import boto3

        client = boto3.client("dynamodb")
        request_id = getattr(context, "aws_request_id", None)
        if not isinstance(request_id, str):
            raise RegistryMutationInputError("registry audit context is unavailable")
        occurred_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
            "+00:00",
            "Z",
        )
    except Exception:
        return {"ok": False, "error": "registry service request failed"}
    return handle_registry_request(
        event,
        client,
        audit_context={"occurredAt": occurred_at, "requestId": request_id},
    )
