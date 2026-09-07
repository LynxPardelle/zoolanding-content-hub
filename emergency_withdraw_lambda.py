"""Operator-only, bounded emergency withdrawal for the THN public projection."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Protocol

import content_hub_v2_projection_manifest as projection
from service_binding_registry_consumer_v2 import (
    APPROVED_PARTITION_KEY,
    APPROVED_SORT_KEY,
    APPROVED_TABLE_NAME,
    RegistryConsumerError,
    load_active_service_binding,
    marshal_item,
    unmarshal_item,
)

REGISTRY_TABLE = APPROVED_TABLE_NAME
PRIVATE_TABLE = "zoolanding-content-hub-test-ThnContentHubV2Metadata"
AUDIT_TABLE = "zoolanding-content-hub-test-ThnContentHubV2Audit"
FUNCTION_NAME = "zoolanding-content-hub-test-ThnV2EmergencyWithdraw"
CHECKPOINT_RECORD_TYPE = "THN_CONTENT_HUB_V2_WITHDRAWAL_CHECKPOINT"
OUTBOX_RECORD_TYPE = "THN_CONTENT_HUB_V2_INVALIDATION_OUTBOX"
AUDIT_RECORD_TYPE = "THN_CONTENT_HUB_V2_WITHDRAWAL_AUDIT"
_EXPECTED_EVENT_FIELDS = frozenset({"schemaVersion", "operation", "writerEpoch"})
_SAFE_TABLE_RE = re.compile(r"^[A-Za-z0-9_.-]{3,255}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]+$")
_REGISTRY_FENCED_FIELDS = (
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
_MANIFEST_CONDITION_FIELDS = (
    "recordType",
    "schemaVersion",
    "environment",
    "domain",
    "hubId",
    "manifestId",
    "projectionDigest",
    "publicationWriterEpoch",
    "withdrawalEpoch",
    "state",
    "headPageId",
    "initialPageCount",
    "remainingPageCount",
    "initialPointerCount",
    "livePointerCount",
    "completedBatches",
    "stateRevision",
)
_PAGE_CONDITION_FIELDS = (
    "recordType",
    "schemaVersion",
    "environment",
    "domain",
    "hubId",
    "manifestId",
    "pageId",
    "nextPageId",
    "pointerCount",
    "livePointers",
    "pageDigest",
    "state",
)
_CHECKPOINT_FIELDS = frozenset(
    {
        "pk",
        "sk",
        "recordType",
        "schemaVersion",
        "environment",
        "domain",
        "hubId",
        "manifestId",
        "projectionDigest",
        "writerEpoch",
        "status",
        "completedBatches",
        "processedPageCount",
        "processedPointerCount",
        "remainingPageCount",
        "remainingPointerCount",
        "manifestStateRevision",
    }
)


class EmergencyWithdrawalError(RuntimeError):
    """The closed emergency-withdrawal contract could not be satisfied."""


def _reject() -> None:
    raise EmergencyWithdrawalError("emergency withdrawal is unavailable")


def _parse_event(value: Any) -> int:
    if not isinstance(value, Mapping) or set(value) != _EXPECTED_EVENT_FIELDS:
        _reject()
    if value.get("schemaVersion") != 1 or type(value.get("schemaVersion")) is not int:
        _reject()
    if value.get("operation") != "withdrawHub":
        _reject()
    writer_epoch = value.get("writerEpoch")
    if type(writer_epoch) is not int or writer_epoch < 1:
        _reject()
    return writer_epoch


def _validate_binding(value: Any, *, writer_epoch: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _reject()
    binding = dict(value)
    expected = {
        "environment": projection.ENVIRONMENT,
        "domain": projection.DOMAIN,
        "serviceBindingId": "thn-journal-test-v2",
        "hubId": projection.HUB_ID,
        "tenantId": "thehairnarrative-com",
        "authProfileId": "journal-owner",
        "activationStatus": "active",
        "writerMode": "disabled",
        "writerEpoch": writer_epoch,
    }
    if any(
        binding.get(field) != expected_value
        for field, expected_value in expected.items()
    ):
        _reject()
    if any(field not in binding for field in _REGISTRY_FENCED_FIELDS):
        _reject()
    return deepcopy(binding)


def _checkpoint_key(writer_epoch: int) -> dict[str, str]:
    return {
        "pk": projection.MANIFEST_PK,
        "sk": f"WITHDRAWAL#{writer_epoch:020d}",
    }


def _build_checkpoint(
    manifest: Mapping[str, Any], *, writer_epoch: int
) -> dict[str, Any]:
    return {
        **_checkpoint_key(writer_epoch),
        "recordType": CHECKPOINT_RECORD_TYPE,
        "schemaVersion": 1,
        "environment": projection.ENVIRONMENT,
        "domain": projection.DOMAIN,
        "hubId": projection.HUB_ID,
        "manifestId": manifest["manifestId"],
        "projectionDigest": manifest["projectionDigest"],
        "writerEpoch": writer_epoch,
        "status": "complete" if manifest["state"] == "withdrawn" else "in_progress",
        "completedBatches": manifest["completedBatches"],
        "processedPageCount": (
            manifest["initialPageCount"] - manifest["remainingPageCount"]
        ),
        "processedPointerCount": (
            manifest["initialPointerCount"] - manifest["livePointerCount"]
        ),
        "remainingPageCount": manifest["remainingPageCount"],
        "remainingPointerCount": manifest["livePointerCount"],
        "manifestStateRevision": manifest["stateRevision"],
    }


def _validate_checkpoint(
    value: Any,
    *,
    manifest: Mapping[str, Any],
    writer_epoch: int,
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _CHECKPOINT_FIELDS:
        _reject()
    checkpoint = dict(value)
    if checkpoint != _build_checkpoint(manifest, writer_epoch=writer_epoch):
        _reject()
    return deepcopy(checkpoint)


def _ordered_invalidation_paths(
    pointers: tuple[dict[str, Any], ...],
) -> tuple[str, ...]:
    ordered = list(projection.GLOBAL_INVALIDATION_PATHS)
    for pointer in pointers:
        ordered.extend(pointer["invalidationPaths"])
    unique = tuple(dict.fromkeys(ordered))
    if len(unique) > 2_000:
        _reject()
    return unique


@dataclass(frozen=True)
class WithdrawalBatch:
    writer_epoch: int
    batch_number: int
    binding: dict[str, Any]
    manifest_before: dict[str, Any]
    manifest_after: dict[str, Any]
    page_before: dict[str, Any] | None
    page_after: dict[str, Any] | None
    checkpoint_before: dict[str, Any] | None
    checkpoint_after: dict[str, Any]
    pointers: tuple[dict[str, Any], ...]
    invalidation_paths: tuple[str, ...]


class EmergencyWithdrawalRuntime(Protocol):
    def load_closed_binding(self, writer_epoch: int) -> Mapping[str, Any]: ...

    def load_projection_manifest(self) -> Mapping[str, Any] | None: ...

    def load_projection_page(self, page_id: str) -> Mapping[str, Any] | None: ...

    def load_checkpoint(self, writer_epoch: int) -> Mapping[str, Any] | None: ...

    def commit_batch(self, batch: WithdrawalBatch) -> None: ...


def _response(manifest: Mapping[str, Any], *, writer_epoch: int) -> dict[str, Any]:
    complete = manifest["state"] == "withdrawn"
    return {
        "ok": True,
        "status": "complete" if complete else "in_progress",
        "writerEpoch": writer_epoch,
        "processedPointers": manifest["initialPointerCount"]
        - manifest["livePointerCount"],
        "remainingPointers": manifest["livePointerCount"],
        "continuationRequired": not complete,
    }


def handle_withdrawal(
    event: Mapping[str, Any], *, runtime: EmergencyWithdrawalRuntime
) -> dict[str, Any]:
    """Withdraw one bounded manifest page under the already-disabled epoch."""

    writer_epoch = _parse_event(event)
    try:
        binding = _validate_binding(
            runtime.load_closed_binding(writer_epoch),
            writer_epoch=writer_epoch,
        )
        manifest = projection.validate_projection_manifest(
            runtime.load_projection_manifest()
        )
        checkpoint_raw = runtime.load_checkpoint(writer_epoch)

        if manifest["state"] == "live":
            if checkpoint_raw is not None:
                _reject()
            checkpoint = None
        else:
            checkpoint = _validate_checkpoint(
                checkpoint_raw,
                manifest=manifest,
                writer_epoch=writer_epoch,
            )

        if manifest["state"] == "withdrawn":
            return _response(manifest, writer_epoch=writer_epoch)
        if (
            manifest["state"] == "withdrawing"
            and manifest["withdrawalEpoch"] != writer_epoch
        ):
            _reject()

        page_before = None
        page_after = None
        pointers: tuple[dict[str, Any], ...] = ()
        if manifest["remainingPageCount"] == 0:
            manifest_after = projection.complete_empty_projection_manifest(
                manifest,
                withdrawal_epoch=writer_epoch,
            )
        else:
            page_before = projection.validate_projection_page(
                runtime.load_projection_page(manifest["headPageId"])
            )
            manifest_after, page_after = projection.advance_projection_manifest(
                manifest,
                page_before,
                withdrawal_epoch=writer_epoch,
            )
            pointers = tuple(deepcopy(page_before["livePointers"]))

        checkpoint_after = _build_checkpoint(
            manifest_after,
            writer_epoch=writer_epoch,
        )
        batch = WithdrawalBatch(
            writer_epoch=writer_epoch,
            batch_number=manifest_after["completedBatches"],
            binding=binding,
            manifest_before=manifest,
            manifest_after=manifest_after,
            page_before=page_before,
            page_after=page_after,
            checkpoint_before=checkpoint,
            checkpoint_after=checkpoint_after,
            pointers=pointers,
            invalidation_paths=_ordered_invalidation_paths(pointers),
        )
        runtime.commit_batch(batch)
        return _response(manifest_after, writer_epoch=writer_epoch)
    except EmergencyWithdrawalError:
        raise
    except Exception:  # noqa: BLE001 - every adapter failure must collapse to one safe error
        _reject()


def _exact_condition(
    item: Mapping[str, Any], fields: tuple[str, ...], *, prefix: str
) -> tuple[str, dict[str, str], dict[str, Any]]:
    names = {f"#{prefix}{index}": field for index, field in enumerate(fields)}
    values = {
        f":{prefix}{index}": marshal_item({"value": item[field]})["value"]
        for index, field in enumerate(fields)
    }
    expression = " AND ".join(
        f"#{prefix}{index} = :{prefix}{index}" for index in range(len(fields))
    )
    return expression, names, values


def _registry_condition(binding: Mapping[str, Any]) -> dict[str, Any]:
    expression, names, values = _exact_condition(
        binding,
        _REGISTRY_FENCED_FIELDS,
        prefix="r",
    )
    return {
        "ConditionCheck": {
            "TableName": REGISTRY_TABLE,
            "Key": marshal_item(
                {"pk": APPROVED_PARTITION_KEY, "sk": APPROVED_SORT_KEY}
            ),
            "ConditionExpression": expression,
            "ExpressionAttributeNames": names,
            "ExpressionAttributeValues": values,
        }
    }


def _conditional_put(
    *,
    table_name: str,
    item: Mapping[str, Any],
    expected: Mapping[str, Any] | None,
    fields: tuple[str, ...],
    prefix: str,
) -> dict[str, Any]:
    put: dict[str, Any] = {"TableName": table_name, "Item": marshal_item(item)}
    if expected is None:
        put.update(
            {
                "ConditionExpression": "attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
                "ExpressionAttributeNames": {"#pk": "pk", "#sk": "sk"},
            }
        )
    else:
        expression, names, values = _exact_condition(expected, fields, prefix=prefix)
        put.update(
            {
                "ConditionExpression": expression,
                "ExpressionAttributeNames": names,
                "ExpressionAttributeValues": values,
            }
        )
    return {"Put": put}


def _pointer_delete(pointer: Mapping[str, Any], *, table_name: str) -> dict[str, Any]:
    pointer = projection.validate_projection_pointer(pointer)
    pointer_type = pointer["pointerType"]
    bundle_key = (
        f"content-hubs/{projection.ENVIRONMENT}/{projection.HUB_ID}/published/"
        f"{projection.DOMAIN}/{pointer['locale']}/{pointer['articleId']}/"
        f"{pointer['revisionId']}/bundle.json"
    )
    expected: dict[str, Any] = {
        "hubId": projection.HUB_ID,
        "articleId": pointer["articleId"],
    }
    if pointer_type == "article":
        expected.update(
            {
                "itemFamily": "ARTICLE",
                "locale": pointer["locale"],
                "publishedBundleKey": bundle_key,
                "status": "published",
                "visibility": "public",
            }
        )
    elif pointer_type == "locale-path":
        expected.update(
            {
                "itemFamily": "SLUG",
                "revisionId": pointer["revisionId"],
                "path": pointer["path"],
                "publishedBundleKey": bundle_key,
            }
        )
    elif pointer_type == "category-index":
        expected.update(
            {
                "itemFamily": "CATEGORY_INDEX",
                "locale": pointer["locale"],
                "revisionId": pointer["revisionId"],
                "categorySlug": pointer["categorySlug"],
            }
        )
    elif pointer_type == "public-media":
        expected.update(
            {
                "recordType": "THN_CONTENT_HUB_V2_LIVE_MEDIA_MANIFEST",
                "locale": pointer["locale"],
                "revisionId": pointer["revisionId"],
                "status": "published",
                "visibility": "public",
                "deliveryState": "live",
            }
        )
    else:
        _reject()
    fields = tuple(sorted(expected))
    match, names, values = _exact_condition(expected, fields, prefix="p")
    names = {"#pk": "pk", **names}
    return {
        "Delete": {
            "TableName": table_name,
            "Key": marshal_item({"pk": pointer["pk"], "sk": pointer["sk"]}),
            "ConditionExpression": f"attribute_not_exists(#pk) OR ({match})",
            "ExpressionAttributeNames": names,
            "ExpressionAttributeValues": values,
        }
    }


def _outbox_item(batch: WithdrawalBatch) -> dict[str, Any]:
    return {
        "pk": (
            f"OUTBOX#{projection.ENVIRONMENT}#{projection.DOMAIN}#"
            f"{projection.HUB_ID}#WITHDRAWAL#{batch.writer_epoch:020d}"
        ),
        "sk": f"BATCH#{batch.batch_number:020d}",
        "recordType": OUTBOX_RECORD_TYPE,
        "schemaVersion": 1,
        "environment": projection.ENVIRONMENT,
        "domain": projection.DOMAIN,
        "hubId": projection.HUB_ID,
        "source": "emergency-withdraw",
        "manifestId": batch.manifest_after["manifestId"],
        "projectionDigest": batch.manifest_after["projectionDigest"],
        "writerEpoch": batch.writer_epoch,
        "batchNumber": batch.batch_number,
        "status": "pending",
        "paths": list(batch.invalidation_paths),
        "pathCount": len(batch.invalidation_paths),
        "attemptCount": 0,
    }


def _audit_item(batch: WithdrawalBatch) -> dict[str, Any]:
    return {
        "pk": (
            f"AUDIT#{projection.ENVIRONMENT}#{projection.DOMAIN}#"
            f"{projection.HUB_ID}#WITHDRAWAL#{batch.writer_epoch:020d}"
        ),
        "sk": f"BATCH#{batch.batch_number:020d}",
        "recordType": AUDIT_RECORD_TYPE,
        "schemaVersion": 1,
        "environment": projection.ENVIRONMENT,
        "domain": projection.DOMAIN,
        "hubId": projection.HUB_ID,
        "decision": "projection_batch_withdrawn",
        "manifestId": batch.manifest_after["manifestId"],
        "projectionDigest": batch.manifest_after["projectionDigest"],
        "writerEpoch": batch.writer_epoch,
        "batchNumber": batch.batch_number,
        "withdrawnPointerCount": len(batch.pointers),
        "remainingPointerCount": batch.manifest_after["livePointerCount"],
        "status": batch.checkpoint_after["status"],
    }


class AwsEmergencyWithdrawalRuntime:
    """Exact-key DynamoDB adapter; it has no query, scan, S3, or HTTP path."""

    def __init__(
        self,
        *,
        dynamodb_client: Any,
        private_table_name: str,
        public_table_name: str,
        audit_table_name: str,
        expected_descriptor: Mapping[str, Any],
        trusted_resource_scope: Mapping[str, Any],
    ) -> None:
        if private_table_name != PRIVATE_TABLE or audit_table_name != AUDIT_TABLE:
            _reject()
        if (
            not isinstance(public_table_name, str)
            or not _SAFE_TABLE_RE.fullmatch(public_table_name)
            or public_table_name in {PRIVATE_TABLE, AUDIT_TABLE, REGISTRY_TABLE}
        ):
            _reject()
        if not isinstance(expected_descriptor, Mapping) or set(expected_descriptor) != {
            "descriptorVersionId",
            "descriptorSha256",
            "authPolicyVersion",
        }:
            _reject()
        if not isinstance(trusted_resource_scope, Mapping) or set(
            trusted_resource_scope
        ) != {
            "partition",
            "accountId",
            "region",
        }:
            _reject()
        if (
            trusted_resource_scope.get("partition")
            not in {"aws", "aws-us-gov", "aws-cn"}
            or not isinstance(trusted_resource_scope.get("accountId"), str)
            or not _ACCOUNT_ID_RE.fullmatch(trusted_resource_scope["accountId"])
            or not isinstance(trusted_resource_scope.get("region"), str)
            or not _REGION_RE.fullmatch(trusted_resource_scope["region"])
        ):
            _reject()
        descriptor_version = expected_descriptor.get("descriptorVersionId")
        descriptor_digest = expected_descriptor.get("descriptorSha256")
        policy_version = expected_descriptor.get("authPolicyVersion")
        if (
            not isinstance(descriptor_version, str)
            or not _SAFE_ID_RE.fullmatch(descriptor_version)
            or not isinstance(descriptor_digest, str)
            or not _SHA256_RE.fullmatch(descriptor_digest)
            or not isinstance(policy_version, str)
            or not _SAFE_ID_RE.fullmatch(policy_version)
        ):
            _reject()
        self.dynamodb_client = dynamodb_client
        self.private_table_name = private_table_name
        self.public_table_name = public_table_name
        self.audit_table_name = audit_table_name
        self.expected_descriptor = deepcopy(dict(expected_descriptor))
        self.trusted_resource_scope = deepcopy(dict(trusted_resource_scope))

    @classmethod
    def from_environment(cls) -> AwsEmergencyWithdrawalRuntime:
        if (
            os.environ.get("CONTENT_HUB_ENVIRONMENT") != projection.ENVIRONMENT
            or os.environ.get("CONTENT_HUB_DOMAIN") != projection.DOMAIN
            or os.environ.get("CONTENT_HUB_ID") != projection.HUB_ID
            or os.environ.get("SERVICE_BINDING_REGISTRY_TABLE_NAME") != REGISTRY_TABLE
        ):
            _reject()
        try:
            import boto3

            return cls(
                dynamodb_client=boto3.client("dynamodb"),
                private_table_name=os.environ["THN_CONTENT_HUB_METADATA_TABLE_NAME"],
                public_table_name=os.environ["CONTENT_HUB_METADATA_TABLE_NAME"],
                audit_table_name=os.environ["THN_CONTENT_HUB_AUDIT_TABLE_NAME"],
                expected_descriptor={
                    "descriptorVersionId": os.environ[
                        "THN_CONTENT_HUB_DESCRIPTOR_VERSION_ID"
                    ],
                    "descriptorSha256": os.environ["THN_CONTENT_HUB_DESCRIPTOR_SHA256"],
                    "authPolicyVersion": os.environ[
                        "THN_CONTENT_HUB_AUTH_POLICY_VERSION"
                    ],
                },
                trusted_resource_scope={
                    "partition": os.environ["THN_CONTENT_HUB_AWS_PARTITION"],
                    "accountId": os.environ["THN_CONTENT_HUB_AWS_ACCOUNT_ID"],
                    "region": os.environ["THN_CONTENT_HUB_AWS_REGION"],
                },
            )
        except EmergencyWithdrawalError:
            raise
        except Exception:  # noqa: BLE001 - environment and SDK setup fail closed
            _reject()

    def _get_private(self, key: Mapping[str, str]) -> dict[str, Any] | None:
        try:
            response = self.dynamodb_client.get_item(
                TableName=self.private_table_name,
                Key=marshal_item(key),
                ConsistentRead=True,
            )
            item = response.get("Item") if isinstance(response, Mapping) else None
            return unmarshal_item(item) if isinstance(item, Mapping) and item else None
        except Exception:  # noqa: BLE001 - provider details must not escape
            _reject()

    def load_closed_binding(self, writer_epoch: int) -> Mapping[str, Any]:
        try:
            binding = load_active_service_binding(
                self.dynamodb_client,
                expected_descriptor=self.expected_descriptor,
                trusted_resource_scope=self.trusted_resource_scope,
            )
            return _validate_binding(binding, writer_epoch=writer_epoch)
        except (EmergencyWithdrawalError, RegistryConsumerError):
            _reject()

    def load_projection_manifest(self) -> Mapping[str, Any] | None:
        return self._get_private(
            {"pk": projection.MANIFEST_PK, "sk": projection.MANIFEST_SK}
        )

    def load_projection_page(self, page_id: str) -> Mapping[str, Any] | None:
        if not isinstance(page_id, str) or not _SAFE_ID_RE.fullmatch(page_id):
            _reject()
        return self._get_private(
            {"pk": projection.MANIFEST_PK, "sk": f"PAGE#{page_id}"}
        )

    def load_checkpoint(self, writer_epoch: int) -> Mapping[str, Any] | None:
        if type(writer_epoch) is not int or writer_epoch < 1:
            _reject()
        return self._get_private(_checkpoint_key(writer_epoch))

    def commit_batch(self, batch: WithdrawalBatch) -> None:
        if not isinstance(batch, WithdrawalBatch):
            _reject()
        try:
            binding = _validate_binding(
                batch.binding,
                writer_epoch=batch.writer_epoch,
            )
            manifest_before = projection.validate_projection_manifest(
                batch.manifest_before
            )
            if manifest_before["state"] == "live":
                if batch.checkpoint_before is not None:
                    _reject()
                checkpoint_before = None
            else:
                checkpoint_before = _validate_checkpoint(
                    batch.checkpoint_before,
                    manifest=manifest_before,
                    writer_epoch=batch.writer_epoch,
                )

            if batch.page_before is None and batch.page_after is None:
                manifest_after = projection.complete_empty_projection_manifest(
                    manifest_before,
                    withdrawal_epoch=batch.writer_epoch,
                )
                page_before = None
                page_after = None
                pointers: tuple[dict[str, Any], ...] = ()
            elif batch.page_before is not None and batch.page_after is not None:
                page_before = projection.validate_projection_page(batch.page_before)
                manifest_after, page_after = projection.advance_projection_manifest(
                    manifest_before,
                    page_before,
                    withdrawal_epoch=batch.writer_epoch,
                )
                pointers = tuple(deepcopy(page_before["livePointers"]))
            else:
                _reject()

            checkpoint_after = _build_checkpoint(
                manifest_after,
                writer_epoch=batch.writer_epoch,
            )
            invalidation_paths = _ordered_invalidation_paths(pointers)
            if (
                batch.manifest_after != manifest_after
                or batch.page_after != page_after
                or batch.pointers != pointers
                or batch.checkpoint_after != checkpoint_after
                or batch.invalidation_paths != invalidation_paths
                or batch.batch_number != manifest_after["completedBatches"]
            ):
                _reject()
        except EmergencyWithdrawalError:
            raise
        except (KeyError, TypeError, projection.ProjectionManifestError):
            _reject()

        items = [_registry_condition(binding)]
        items.append(
            _conditional_put(
                table_name=self.private_table_name,
                item=manifest_after,
                expected=manifest_before,
                fields=_MANIFEST_CONDITION_FIELDS,
                prefix="m",
            )
        )
        if page_before is not None:
            items.append(
                _conditional_put(
                    table_name=self.private_table_name,
                    item=page_after,
                    expected=page_before,
                    fields=_PAGE_CONDITION_FIELDS,
                    prefix="g",
                )
            )
        items.extend(
            _pointer_delete(pointer, table_name=self.public_table_name)
            for pointer in pointers
        )
        checkpoint_fields = tuple(sorted(_CHECKPOINT_FIELDS - {"pk", "sk"}))
        items.append(
            _conditional_put(
                table_name=self.private_table_name,
                item=checkpoint_after,
                expected=checkpoint_before,
                fields=checkpoint_fields,
                prefix="c",
            )
        )
        items.append(
            _conditional_put(
                table_name=self.private_table_name,
                item=_outbox_item(batch),
                expected=None,
                fields=(),
                prefix="o",
            )
        )
        items.append(
            _conditional_put(
                table_name=self.audit_table_name,
                item=_audit_item(batch),
                expected=None,
                fields=(),
                prefix="a",
            )
        )
        if len(items) > 25:
            _reject()
        token_material = (
            f"{batch.writer_epoch}|{batch.batch_number}|"
            f"{manifest_before['projectionDigest']}|{manifest_before['stateRevision']}"
        )
        token = (
            "thnwd-" + hashlib.sha256(token_material.encode("utf-8")).hexdigest()[:30]
        )
        try:
            self.dynamodb_client.transact_write_items(
                TransactItems=items,
                ClientRequestToken=token,
            )
        except Exception:  # noqa: BLE001 - transaction details must not escape
            _reject()


def _validate_context(context: Any) -> None:
    function_name = getattr(context, "function_name", None)
    invoked_arn = getattr(context, "invoked_function_arn", None)
    if function_name != FUNCTION_NAME or not isinstance(invoked_arn, str):
        _reject()
    if not invoked_arn.endswith(f":function:{FUNCTION_NAME}:test"):
        _reject()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    _parse_event(event)
    _validate_context(context)
    runtime = AwsEmergencyWithdrawalRuntime.from_environment()
    return handle_withdrawal(event, runtime=runtime)


__all__ = [
    "AUDIT_TABLE",
    "FUNCTION_NAME",
    "PRIVATE_TABLE",
    "REGISTRY_TABLE",
    "AwsEmergencyWithdrawalRuntime",
    "EmergencyWithdrawalError",
    "WithdrawalBatch",
    "handle_withdrawal",
    "lambda_handler",
]
