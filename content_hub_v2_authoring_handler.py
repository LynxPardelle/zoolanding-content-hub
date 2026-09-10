"""Closed HTTP dispatch for the isolated THN Content Hub v2 authoring Lambda."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
from typing import Any, Mapping, Sequence

from content_hub_v2_authorization import (
    ContentHubV2AuthorizationError,
    ContentHubV2WriterDisabledError,
    assert_mutation_actor_enabled,
    assert_writer_epoch_current,
    load_authorization_context,
)
from content_hub_v2_registry_fence import (
    RegistryFenceError,
    execute_registry_fenced_transaction,
)
from content_hub_v2_editor_model import EditorValidationError
from content_hub_v2_editor_service import EditorService, EditorConflict, EditorNotFound
from service_binding_registry_consumer_v2 import (
    APPROVED_TABLE_NAME as REGISTRY_TABLE_NAME,
    RegistryConsumerError,
    load_active_service_binding,
)


READ_PATH = "/features/content-hub-v2/read"
ACTION_PATH = "/features/content-hub-v2/action"
ALLOWED_READS = frozenset(
    {"articleList", "articleDetail", "taxonomyList", "assetList", "publicBundlePreview"}
)
ALLOWED_ACTIONS = frozenset(
    {"createArticle", "updatePackage", "uploadAsset", "validate", "publish", "unpublishArticle"}
)

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_ACCOUNT_ID_RE = re.compile(r"^[0-9]{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]+$")

ENVIRONMENT = "test"
DOMAIN = "thehairnarrative.com"
AUTH_PROFILE_ID = "journal-owner"
HUB_ID = "thehairnarrative-com-journal"
COOKIE_NAMESPACE = "endefiz7dkk635k6di6k"
SESSION_COOKIE_NAME = f"__Host-zlp_session_{COOKIE_NAMESPACE}"
CSRF_COOKIE_NAME = f"zlp_csrf_{COOKIE_NAMESPACE}"
CSRF_HEADER_NAME = "x-zlp-csrf"
SESSION_TABLE_NAME = "zoolanding-auth-admin-test-ThnSessionV2"
CURRENT_USER_TABLE_NAME = "zoolanding-auth-admin-test-ThnCurrentUserStateV2"
CURRENT_USER_PARTITION_KEY = "CURRENT_USER#test#thn-journal-test-v2"
AUTHORING_FUNCTION_NAME = "zoolanding-content-hub-test-ThnContentHubV2Authoring"
AUTHORING_FUNCTION_ALIAS = "test"

DESCRIPTOR_VERSION_ENV = "THN_CONTENT_HUB_DESCRIPTOR_VERSION_ID"
DESCRIPTOR_SHA256_ENV = "THN_CONTENT_HUB_DESCRIPTOR_SHA256"
AUTH_POLICY_VERSION_ENV = "THN_CONTENT_HUB_AUTH_POLICY_VERSION"


class AuthoringRequestError(RuntimeError):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class AuthoringRuntimeError(RuntimeError):
    """A private service dependency cannot safely authorize the request."""


def _marshal_dynamodb_value(value: Any) -> dict[str, Any]:
    if value is None:
        return {"NULL": True}
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, str):
        return {"S": value}
    if type(value) is int:
        return {"N": str(value)}
    if isinstance(value, Mapping):
        return {
            "M": {
                str(key): _marshal_dynamodb_value(candidate)
                for key, candidate in value.items()
            }
        }
    if isinstance(value, (list, tuple)):
        return {"L": [_marshal_dynamodb_value(candidate) for candidate in value]}
    raise AuthoringRuntimeError()


def _marshal_dynamodb_item(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): _marshal_dynamodb_value(candidate)
        for key, candidate in value.items()
    }


def _unmarshal_dynamodb_value(value: Any) -> Any:
    if not isinstance(value, Mapping):
        raise AuthoringRuntimeError()
    if set(value) == {"NULL"} and value.get("NULL") is True:
        return None
    if set(value) == {"BOOL"} and isinstance(value.get("BOOL"), bool):
        return value["BOOL"]
    if set(value) == {"S"} and isinstance(value.get("S"), str):
        return value["S"]
    if set(value) == {"N"} and isinstance(value.get("N"), str):
        number = value["N"]
        if not re.fullmatch(r"-?[0-9]+", number):
            raise AuthoringRuntimeError()
        return int(number)
    if set(value) == {"M"} and isinstance(value.get("M"), Mapping):
        return {
            str(key): _unmarshal_dynamodb_value(candidate)
            for key, candidate in value["M"].items()
        }
    if set(value) == {"L"} and isinstance(value.get("L"), list):
        return [_unmarshal_dynamodb_value(candidate) for candidate in value["L"]]
    raise AuthoringRuntimeError()


def _unmarshal_dynamodb_item(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): _unmarshal_dynamodb_value(candidate)
        for key, candidate in value.items()
    }


class AwsAuthoringRuntime:
    """Exact-table, strongly consistent runtime for the dedicated v2 handler."""

    def __init__(self) -> None:
        self._client: Any = None

    def _dynamodb(self) -> Any:
        if self._client is None:
            try:
                import boto3  # type: ignore

                self._client = boto3.client("dynamodb")
            except Exception as error:
                raise AuthoringRuntimeError() from error
        return self._client

    @staticmethod
    def _trusted_resource_scope(context: Any) -> dict[str, str]:
        arn = getattr(context, "invoked_function_arn", "")
        parts = arn.split(":") if isinstance(arn, str) else []
        if (
            len(parts) not in {7, 8}
            or parts[0] != "arn"
            or parts[1] not in {"aws", "aws-us-gov", "aws-cn"}
            or parts[2] != "lambda"
            or not _REGION_RE.fullmatch(parts[3])
            or not _ACCOUNT_ID_RE.fullmatch(parts[4])
            or parts[5] != "function"
            or parts[6] != AUTHORING_FUNCTION_NAME
            or (len(parts) == 8 and parts[7] != AUTHORING_FUNCTION_ALIAS)
        ):
            raise AuthoringRuntimeError()
        return {"partition": parts[1], "region": parts[3], "accountId": parts[4]}

    @staticmethod
    def _expected_descriptor() -> dict[str, str]:
        values = {
            "descriptorVersionId": os.environ.get(DESCRIPTOR_VERSION_ENV, ""),
            "descriptorSha256": os.environ.get(DESCRIPTOR_SHA256_ENV, ""),
            "authPolicyVersion": os.environ.get(AUTH_POLICY_VERSION_ENV, ""),
        }
        if (
            os.environ.get("CONTENT_HUB_ENVIRONMENT") != ENVIRONMENT
            or os.environ.get("CONTENT_HUB_DOMAIN") != DOMAIN
            or os.environ.get("CONTENT_HUB_ID") != HUB_ID
            or os.environ.get("CONTENT_HUB_OWNER_ID") != AUTH_PROFILE_ID
            or os.environ.get("AUTH_SESSION_TABLE_NAME") != SESSION_TABLE_NAME
            or os.environ.get("AUTH_USER_STATE_TABLE_NAME") != CURRENT_USER_TABLE_NAME
            or os.environ.get("SERVICE_BINDING_REGISTRY_TABLE_NAME")
            != REGISTRY_TABLE_NAME
            or not _SAFE_ID_RE.fullmatch(values["descriptorVersionId"])
            or values["descriptorVersionId"] == "BLOCKED"
            or not _SHA256_RE.fullmatch(values["descriptorSha256"])
            or values["descriptorSha256"] == "0" * 64
            or not _SAFE_ID_RE.fullmatch(values["authPolicyVersion"])
            or values["authPolicyVersion"] == "BLOCKED"
        ):
            raise AuthoringRuntimeError()
        return values

    def load_registry(self, context: Any) -> dict[str, Any]:
        try:
            expected_descriptor = self._expected_descriptor()
            trusted_resource_scope = self._trusted_resource_scope(context)
            return load_active_service_binding(
                self._dynamodb(),
                expected_descriptor=expected_descriptor,
                trusted_resource_scope=trusted_resource_scope,
            )
        except RegistryConsumerError:
            raise
        except Exception as error:
            raise AuthoringRuntimeError() from error

    def get_session(
        self, session_id_hash: str, *, consistent_read: bool
    ) -> dict[str, Any] | None:
        return self._get_item(
            SESSION_TABLE_NAME,
            {"sessionIdHash": session_id_hash},
            consistent_read=consistent_read,
        )

    def get_current_user(
        self, subject: str, *, consistent_read: bool
    ) -> dict[str, Any] | None:
        if not isinstance(subject, str) or not _SUBJECT_RE.fullmatch(subject):
            raise AuthoringRuntimeError()
        return self._get_item(
            CURRENT_USER_TABLE_NAME,
            {"pk": CURRENT_USER_PARTITION_KEY, "sk": f"SUBJECT#{subject}"},
            consistent_read=consistent_read,
        )

    def _get_item(
        self,
        table_name: str,
        key: Mapping[str, Any],
        *,
        consistent_read: bool,
    ) -> dict[str, Any] | None:
        try:
            response = self._dynamodb().get_item(
                TableName=table_name,
                Key=_marshal_dynamodb_item(key),
                ConsistentRead=consistent_read,
            )
            raw = response.get("Item") if isinstance(response, Mapping) else None
            return (
                _unmarshal_dynamodb_item(raw)
                if isinstance(raw, Mapping) and raw
                else None
            )
        except Exception as error:
            raise AuthoringRuntimeError() from error

    def commit_mutation(
        self,
        context: Any,
        *,
        authorization_context: Any,
        mutation_items: Sequence[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        """Commit private state only with the authoritative epoch in-transaction."""

        assert_mutation_actor_enabled(authorization_context)
        try:
            return execute_registry_fenced_transaction(
                self._dynamodb(),
                mutation_items=mutation_items,
                expected_descriptor=self._expected_descriptor(),
                expected_writer_mode=authorization_context.writer_mode,
                expected_writer_epoch=authorization_context.writer_epoch,
                trusted_resource_scope=self._trusted_resource_scope(context),
            )
        except RegistryFenceError:
            raise AuthoringRuntimeError() from None
        except Exception as error:
            raise AuthoringRuntimeError() from error

    @staticmethod
    def now_epoch() -> int:
        return int(time.time())

    def get_editor_store(self, context: Any, authorization_context: Any, session_hash: str) -> Any:
        from content_hub_v2_editor_store import AwsEditorStore
        return AwsEditorStore(self, context, authorization_context, session_hash)

    def get_publisher(self, context: Any, authorization_context: Any, session_hash: str) -> Any:
        binding = os.environ.get("THN_CONTENT_HUB_PUBLISHER_ARN", "")
        if not binding:
            return None
        from content_hub_v2_publication_gateway import PublicationGateway
        return PublicationGateway(authorization_context, session_hash, self._trusted_resource_scope(context),
                                  binding, clock=self.now_epoch)


def _request_id(event: Mapping[str, Any]) -> str:
    request_context = event.get("requestContext")
    request_context = request_context if isinstance(request_context, Mapping) else {}
    value = request_context.get("requestId")
    if isinstance(value, str) and _REQUEST_ID_RE.fullmatch(value):
        return value
    return f"req-{time.time_ns()}"


def _method(event: Mapping[str, Any]) -> str:
    request_context = event.get("requestContext")
    request_context = request_context if isinstance(request_context, Mapping) else {}
    http = request_context.get("http")
    http = http if isinstance(http, Mapping) else {}
    return str(http.get("method") or event.get("httpMethod") or "").strip().upper()


def _path(event: Mapping[str, Any]) -> str:
    request_context = event.get("requestContext")
    request_context = request_context if isinstance(request_context, Mapping) else {}
    http = request_context.get("http")
    http = http if isinstance(http, Mapping) else {}
    value = event.get("rawPath") or event.get("path") or http.get("path") or "/"
    return str(value).strip()


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, entry in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = entry
    return value


def _reject_json_constant(_: str) -> Any:
    raise ValueError("non-finite number")


def _payload(event: Mapping[str, Any]) -> dict[str, Any]:
    try:
        raw: Any = event.get("body")
        if event.get("isBase64Encoded") is True and isinstance(raw, str):
            raw = base64.b64decode(raw, validate=True).decode("utf-8")
        if raw in {None, ""}:
            raise ValueError("body required")
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 5_750_000:
            raise ValueError("body too large")
        value = json.loads(raw, object_pairs_hook=_unique_json_object, parse_constant=_reject_json_constant)
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value
    except Exception as error:
        raise AuthoringRequestError(400, "invalid_request", "Invalid content hub request") from error


def _operation(payload: Mapping[str, Any], operation_key: str) -> str:
    input_value = payload.get("input")
    input_value = input_value if isinstance(input_value, Mapping) else {}
    binding = input_value.get("contentHub")
    binding = binding if isinstance(binding, Mapping) else {}
    opposite_key = "action" if operation_key == "read" else "read"
    if opposite_key in binding:
        raise AuthoringRequestError(
            400,
            "invalid_request",
            "Invalid content hub request",
        )
    value = binding.get(operation_key)
    return value if isinstance(value, str) else ""


def _header(event: Mapping[str, Any], name: str) -> str:
    headers = event.get("headers")
    headers = headers if isinstance(headers, Mapping) else {}
    matches = [
        str(value).strip()
        for key, value in headers.items()
        if str(key).lower() == name.lower() and isinstance(value, str)
    ]
    return matches[0] if len(matches) == 1 else ""


def _single_cookie_value(event: Mapping[str, Any], name: str) -> str:
    pairs: list[str] = []
    cookies = event.get("cookies")
    if isinstance(cookies, list):
        pairs.extend(str(cookie) for cookie in cookies if isinstance(cookie, str))
    cookie_header = _header(event, "cookie")
    if cookie_header:
        pairs.extend(part.strip() for part in cookie_header.split(";"))
    values = []
    for pair in pairs:
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        if key.strip() == name:
            values.append(value.strip())
    return values[0] if len(values) == 1 else ""


def _validate_browser_scope(payload: Mapping[str, Any], event: Mapping[str, Any]) -> None:
    input_value = payload.get("input")
    input_value = input_value if isinstance(input_value, Mapping) else {}
    binding = input_value.get("contentHub")
    binding = binding if isinstance(binding, Mapping) else {}
    if (
        payload.get("domain") != DOMAIN
        or binding.get("hubId") != HUB_ID
        or _header(event, "x-zlp-domain") != DOMAIN
        or _header(event, "x-zlp-auth-profile-id") != AUTH_PROFILE_ID
        or _header(event, "x-zlp-content-hub-id") != HUB_ID
    ):
        raise AuthoringRequestError(403, "binding_mismatch", "Content hub access denied")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_csrf(
    event: Mapping[str, Any], authorization_context: Any
) -> None:
    header_value = _header(event, CSRF_HEADER_NAME)
    cookie_value = _single_cookie_value(event, CSRF_COOKIE_NAME)
    if (
        not header_value
        or not cookie_value
        or not hmac.compare_digest(header_value, cookie_value)
        or not hmac.compare_digest(_sha256(header_value), authorization_context.csrf_hash)
    ):
        raise AuthoringRequestError(403, "csrf_denied", "Request verification failed")


def _response(status_code: int, body: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
            "x-content-type-options": "nosniff",
        },
        "body": json.dumps(dict(body), separators=(",", ":"), ensure_ascii=False),
    }


def _error_response(error: AuthoringRequestError, request_id: str) -> dict[str, Any]:
    return _response(
        error.status_code,
        {
            "ok": False,
            "code": error.code,
            "error": error.message,
            "message": error.message,
            "requestId": request_id,
        },
    )


def handle_request(
    event: Any,
    context: Any,
    *,
    runtime: Any = None,
) -> dict[str, Any]:
    """Reject unknown v2 operations before loading any private dependency."""

    request_id = _request_id(event if isinstance(event, Mapping) else {})
    try:
        if not isinstance(event, Mapping):
            raise AuthoringRequestError(
                400,
                "invalid_request",
                "Invalid content hub request",
            )
        if _method(event) != "POST":
            raise AuthoringRequestError(404, "not_found", "Content hub route not found")
        path = _path(event)
        if path == READ_PATH:
            operation_key = "read"
            allowed = ALLOWED_READS
        elif path == ACTION_PATH:
            operation_key = "action"
            allowed = ALLOWED_ACTIONS
        else:
            raise AuthoringRequestError(404, "not_found", "Content hub route not found")
        payload = _payload(event)
        operation = _operation(payload, operation_key)
        if operation not in allowed:
            raise AuthoringRequestError(
                400,
                "unsupported_operation",
                "Unsupported content hub operation",
            )
        _validate_browser_scope(payload, event)
        private_runtime = runtime if runtime is not None else AwsAuthoringRuntime()
        registry_record = private_runtime.load_registry(context)
        if registry_record.get("cookieNamespace") != COOKIE_NAMESPACE:
            raise AuthoringRuntimeError()
        session_value = _single_cookie_value(event, SESSION_COOKIE_NAME)
        if not session_value:
            raise AuthoringRequestError(401, "auth_required", "Authentication required")
        authorization_context = load_authorization_context(
            private_runtime,
            session_id_hash=_sha256(session_value),
            registry_record=registry_record,
            now_epoch=private_runtime.now_epoch(),
        )
        if operation_key == "action":
            _require_csrf(event, authorization_context)
            assert_mutation_actor_enabled(authorization_context)
            assert_writer_epoch_current(authorization_context, registry_record)
        if not callable(getattr(private_runtime, "get_editor_store", None)):
            raise AuthoringRequestError(503, "feature_not_ready", "Content hub service is temporarily unavailable")

        def reauthorize() -> None:
            fresh_registry = private_runtime.load_registry(context)
            fresh = load_authorization_context(private_runtime, session_id_hash=_sha256(session_value),
                registry_record=fresh_registry, now_epoch=private_runtime.now_epoch())
            if fresh != authorization_context:
                raise ContentHubV2AuthorizationError()
            if operation_key == "action":
                assert_mutation_actor_enabled(fresh)

        store = private_runtime.get_editor_store(context, authorization_context, _sha256(session_value))
        publisher = (private_runtime.get_publisher(context, authorization_context, _sha256(session_value))
                     if callable(getattr(private_runtime, "get_publisher", None)) else None)
        service = EditorService(store, purpose=authorization_context.account_purpose, authorize=reauthorize, publisher=publisher,
                                uploader=getattr(store, "upload_asset", None))
        binding = payload["input"]["contentHub"]
        if set(binding) - {"read", "action", "hubId", "data"}:
            raise EditorValidationError("invalid_request")
        result = service.run(operation, binding.get("data", {}))
        if operation in {"articleDetail", "createArticle", "updatePackage"}:
            available = publisher is not None and authorization_context.writer_mode == {
                "qa": "qa-only", "client-owner": "client-owner"}[authorization_context.account_purpose]
            result = {**result, "publicationAvailable": available}
        return _response(200, {"ok": True, "data": result, "requestId": request_id})
    except EditorConflict:
        return _error_response(AuthoringRequestError(409, "edit_conflict", "The article changed; reload before saving"), request_id)
    except EditorNotFound:
        return _error_response(AuthoringRequestError(404, "not_found", "Article not found"), request_id)
    except EditorValidationError as error:
        # A publisher may have committed before losing its response. Keep this
        # retryable so the client retains the original idempotency key.
        status = 503 if error.code in {"feature_not_ready", "publication_unavailable"} else 400
        return _error_response(AuthoringRequestError(status, error.code, "Content hub request could not be completed"), request_id)
    except AuthoringRequestError as error:
        return _error_response(error, request_id)
    except ContentHubV2WriterDisabledError:
        return _error_response(
            AuthoringRequestError(403, "writer_disabled", "Authoring changes are unavailable"),
            request_id,
        )
    except ContentHubV2AuthorizationError:
        return _error_response(
            AuthoringRequestError(401, "auth_required", "Authentication required"),
            request_id,
        )
    except (RegistryConsumerError, AuthoringRuntimeError):
        return _error_response(
            AuthoringRequestError(
                503,
                "service_unavailable",
                "Content hub service is temporarily unavailable",
            ),
            request_id,
        )
    except Exception:
        return _error_response(
            AuthoringRequestError(
                503,
                "service_unavailable",
                "Content hub service is temporarily unavailable",
            ),
            request_id,
        )


__all__ = [
    "ACTION_PATH",
    "ALLOWED_ACTIONS",
    "ALLOWED_READS",
    "AwsAuthoringRuntime",
    "READ_PATH",
    "handle_request",
]
