#!/usr/bin/env python3
"""Invoke the private THN registry mutation boundary.

The caller must be the exact TEST operator role (or one of its OIDC sessions).
This client never creates a DynamoDB client, accepts a table/function selector,
or prints the Lambda's untrusted response without a closed safe projection.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


APPROVED_FUNCTION_NAME = "zoolanding-content-hub-test-ThnServiceBindingRegistryV2Mutation"
_ROLE_ARN_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/(zoolanding-thn-registry-test-operator)$"
)
_ASSUMED_ROLE_ARN_RE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):sts::([0-9]{12}):assumed-role/(zoolanding-thn-registry-test-operator)/[^/]{1,128}$"
)
_MAX_RECORD_FILE_BYTES = 256 * 1024
_MAX_RESPONSE_BYTES = 64 * 1024
_SAFE_RESULT_FIELDS = (
    "ok",
    "operation",
    "environment",
    "domain",
    "serviceBindingId",
    "descriptorVersionId",
    "registryRevision",
)


class OperatorAuthorizationError(PermissionError):
    """The active AWS principal is not the configured TEST operator role."""


class OperatorInputError(ValueError):
    """The operator command input is unsafe or malformed."""


class OperatorServiceError(RuntimeError):
    """A provider operation failed without exposing its internal details."""


def require_named_operator(caller_arn: str, trusted_account_id: str) -> str:
    if not re.fullmatch(r"[0-9]{12}", str(trusted_account_id or "")):
        raise OperatorAuthorizationError("trusted registry account is invalid")
    caller = str(caller_arn or "")
    direct = _ROLE_ARN_RE.fullmatch(caller)
    if direct:
        partition, account_id, role_name = direct.groups()
        if account_id == trusted_account_id:
            return f"arn:{partition}:iam::{account_id}:role/{role_name}"
    assumed = _ASSUMED_ROLE_ARN_RE.fullmatch(caller)
    if assumed:
        partition, account_id, role_name = assumed.groups()
        if account_id == trusted_account_id:
            return f"arn:{partition}:iam::{account_id}:role/{role_name}"
    raise OperatorAuthorizationError("active AWS principal is not the named TEST operator role")


def load_definition(path: str) -> Mapping[str, Any]:
    record_path = Path(path).resolve()
    try:
        size = record_path.stat().st_size
    except OSError as error:
        raise OperatorInputError("record file cannot be read") from error
    if size < 2 or size > _MAX_RECORD_FILE_BYTES:
        raise OperatorInputError("record file size is invalid")
    try:
        payload = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OperatorInputError("record file must contain valid UTF-8 JSON") from error
    if not isinstance(payload, Mapping):
        raise OperatorInputError("record file must contain one JSON object")
    return payload


def _build_payload(
    operation: str,
    definition: Mapping[str, Any],
    *,
    expected_registry_revision: int | None,
    expected_writer_epoch: int | None,
) -> dict[str, Any]:
    if operation == "reserve":
        if expected_registry_revision is not None or expected_writer_epoch is not None:
            raise OperatorInputError("reserve does not accept concurrency fields")
        return {"operation": "reserve", "definition": dict(definition)}
    if operation == "update":
        if (
            isinstance(expected_registry_revision, bool)
            or not isinstance(expected_registry_revision, int)
            or expected_registry_revision < 1
            or isinstance(expected_writer_epoch, bool)
            or not isinstance(expected_writer_epoch, int)
            or expected_writer_epoch < 1
        ):
            raise OperatorInputError("update requires positive concurrency fields")
        return {
            "operation": "update",
            "definition": dict(definition),
            "expectedRegistryRevision": expected_registry_revision,
            "expectedWriterEpoch": expected_writer_epoch,
        }
    raise OperatorInputError("unsupported operation")


def _read_lambda_payload(response: Mapping[str, Any]) -> Mapping[str, Any]:
    if response.get("StatusCode") != 200 or response.get("FunctionError"):
        raise OperatorServiceError("registry service request failed")
    stream = response.get("Payload")
    if not hasattr(stream, "read"):
        raise OperatorServiceError("registry service request failed")
    try:
        raw = stream.read(_MAX_RESPONSE_BYTES + 1)
        if not isinstance(raw, bytes) or len(raw) > _MAX_RESPONSE_BYTES:
            raise ValueError
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise OperatorServiceError("registry service request failed") from None
    if not isinstance(payload, Mapping) or payload.get("ok") is not True:
        raise OperatorServiceError("registry service request rejected")
    return payload


def _safe_result(payload: Mapping[str, Any]) -> dict[str, Any]:
    projected = {field: payload.get(field) for field in _SAFE_RESULT_FIELDS}
    if projected["ok"] is not True:
        raise OperatorServiceError("registry service request failed")
    if projected["operation"] not in {"reserve", "update"}:
        raise OperatorServiceError("registry service request failed")
    for field in ("environment", "domain", "serviceBindingId", "descriptorVersionId"):
        if not isinstance(projected[field], str) or not projected[field]:
            raise OperatorServiceError("registry service request failed")
    revision = projected["registryRevision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise OperatorServiceError("registry service request failed")
    if projected["operation"] == "reserve":
        if not isinstance(payload.get("created"), bool):
            raise OperatorServiceError("registry service request failed")
        projected["created"] = payload["created"]
    return projected


def execute_operation(
    session: Any,
    *,
    operation: str,
    definition: Mapping[str, Any],
    expected_registry_revision: int | None = None,
    expected_writer_epoch: int | None = None,
) -> dict[str, Any]:
    identity = session.client("sts").get_caller_identity()
    if not isinstance(identity, Mapping):
        raise OperatorAuthorizationError("active AWS principal identity is invalid")
    require_named_operator(str(identity.get("Arn") or ""), str(identity.get("Account") or ""))
    payload = _build_payload(
        operation,
        definition,
        expected_registry_revision=expected_registry_revision,
        expected_writer_epoch=expected_writer_epoch,
    )
    try:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError):
        raise OperatorInputError("record file contains unsupported JSON values") from None
    if len(encoded) > _MAX_RECORD_FILE_BYTES:
        raise OperatorInputError("record file size is invalid")
    try:
        response = session.client("lambda").invoke(
            FunctionName=APPROVED_FUNCTION_NAME,
            InvocationType="RequestResponse",
            Payload=encoded,
        )
    except Exception:
        raise OperatorServiceError("registry service request failed") from None
    if not isinstance(response, Mapping):
        raise OperatorServiceError("registry service request failed")
    return _safe_result(_read_lambda_payload(response))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Operate the private THN v2 service-binding registry.")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"))
    subparsers = parser.add_subparsers(dest="operation", required=True)
    reserve = subparsers.add_parser("reserve", help="Conditionally reserve the approved TASK-008 binding.")
    reserve.add_argument("--record-file", required=True)
    update = subparsers.add_parser("update", help="Conditionally replace the approved TASK-008 binding.")
    update.add_argument("--record-file", required=True)
    update.add_argument("--expected-registry-revision", type=int, required=True)
    update.add_argument("--expected-writer-epoch", type=int, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        definition = load_definition(args.record_file)
        import boto3

        session = boto3.Session(region_name=args.region)
        summary = execute_operation(
            session,
            operation=args.operation,
            definition=definition,
            expected_registry_revision=getattr(args, "expected_registry_revision", None),
            expected_writer_epoch=getattr(args, "expected_writer_epoch", None),
        )
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return 0
    except (OperatorAuthorizationError, OperatorInputError, OperatorServiceError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, separators=(",", ":")), file=sys.stderr)
        return 2
    except Exception:
        print(json.dumps({"ok": False, "error": "operator request failed"}, separators=(",", ":")), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
