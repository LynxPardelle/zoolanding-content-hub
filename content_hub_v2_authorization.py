"""Fail-closed authorization contract for the isolated THN Content Hub v2.

The dedicated v2 handler imports this module; the shared v1 handler remains
independent so its routes and authorization behavior cannot change implicitly.
"""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


ALLOWED_ACCOUNT_PURPOSES = frozenset({"qa", "client-owner"})
ALLOWED_WRITER_MODES = frozenset({"disabled", "qa-only", "client-owner"})

THN_CURRENT_USER_SCOPE = {
    "environment": "test",
    "domain": "thehairnarrative.com",
    "serviceBindingId": "thn-journal-test-v2",
    "authProfileId": "journal-owner",
    "tenantId": "thehairnarrative-com",
    "hubId": "thehairnarrative-com-journal",
}
THN_CURRENT_USER_PARTITION_KEY = "CURRENT_USER#test#thn-journal-test-v2"
THN_AUTH_PROFILE_ROLE = "journal-owner"
SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 12 * 60 * 60

_LIST_READ_OPERATIONS = frozenset({"articleList", "assetList"})
_REFERENCE_READ_OPERATIONS = frozenset({"taxonomyList"})
_DIRECT_READ_OPERATIONS = frozenset({"articleDetail", "publicBundlePreview"})
_CREATE_OPERATION = "createArticle"
_RECORD_MUTATION_OPERATIONS = frozenset(
    {"updatePackage", "uploadAsset", "validate", "publish", "unpublishArticle"}
)
_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
_SAFE_SUBJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}$")
_SAFE_RECORD_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ContentHubV2AuthorizationError(RuntimeError):
    """The request cannot be authorized without leaking private state."""


class ContentHubV2NotFoundError(ContentHubV2AuthorizationError):
    """A direct private record is invisible to the current actor purpose."""


class ContentHubV2WriterDisabledError(ContentHubV2AuthorizationError):
    """The current registry mode does not permit this actor to mutate state."""


@dataclass(frozen=True)
class AuthorizationContext:
    subject: str
    account_purpose: str
    session_version: int
    csrf_hash: str
    roles: tuple[str, ...]
    writer_mode: str
    writer_epoch: int
    environment: str
    domain: str
    service_binding_id: str
    auth_profile_id: str
    tenant_id: str
    hub_id: str


def _reject() -> None:
    raise ContentHubV2AuthorizationError(
        "authorization context is unavailable"
    ) from None


def _not_found() -> None:
    raise ContentHubV2NotFoundError("resource is unavailable")


def _positive_integer(value: Any) -> int:
    if type(value) is not int or value < 1:
        _reject()
    return value


def _validated_registry_scope(record: Any) -> tuple[dict[str, str], str, int]:
    if not isinstance(record, Mapping):
        _reject()
    scope = {field: record.get(field) for field in THN_CURRENT_USER_SCOPE}
    if scope != THN_CURRENT_USER_SCOPE:
        _reject()
    if record.get("activationStatus") != "active":
        _reject()
    writer_mode = record.get("writerMode")
    if writer_mode not in ALLOWED_WRITER_MODES:
        _reject()
    return dict(scope), str(writer_mode), _positive_integer(record.get("writerEpoch"))


def _require_record_scope(record: Mapping[str, Any], scope: Mapping[str, str]) -> None:
    if any(record.get(field) != expected for field, expected in scope.items()):
        _reject()


def _validate_session(
    value: Any,
    *,
    scope: Mapping[str, str],
    expected_session_id_hash: str,
    now_epoch: int,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _reject()
    subject = value.get("subject")
    purpose = value.get("accountPurpose")
    roles = value.get("roles")
    timestamps = (
        value.get("createdAt"),
        value.get("lastSeenAt"),
        value.get("idleExpiresAt"),
        value.get("absoluteExpiresAt"),
        value.get("expiresAt"),
    )
    if (
        value.get("recordType") != "authSessionV2"
        or value.get("sessionIdHash") != expected_session_id_hash
        or value.get("scope") != scope
        or not isinstance(subject, str)
        or not _SAFE_SUBJECT_RE.fullmatch(subject)
        or purpose not in ALLOWED_ACCOUNT_PURPOSES
        or value.get("revokedAt") is not None
        or not isinstance(value.get("csrfHash"), str)
        or not _HASH_RE.fullmatch(value["csrfHash"])
        or not isinstance(value.get("accountHash"), str)
        or not _HASH_RE.fullmatch(value["accountHash"])
        or not isinstance(roles, list)
        or roles != [THN_AUTH_PROFILE_ROLE]
        or not all(type(timestamp) is int for timestamp in timestamps)
    ):
        _reject()
    created_at, last_seen_at, idle_expires_at, absolute_expires_at, expires_at = timestamps
    if (
        not 0 <= created_at <= last_seen_at
        or last_seen_at > idle_expires_at
        or idle_expires_at > last_seen_at + SESSION_IDLE_SECONDS
        or idle_expires_at > absolute_expires_at
        or absolute_expires_at > created_at + SESSION_ABSOLUTE_SECONDS
        or absolute_expires_at != expires_at
        or idle_expires_at <= now_epoch
        or absolute_expires_at <= now_epoch
    ):
        _reject()
    cognito_username = value.get("cognitoUsername")
    if purpose == "client-owner" and (
        not isinstance(cognito_username, str) or not cognito_username
    ):
        _reject()
    version = _positive_integer(value.get("sessionVersion"))
    return {
        "subject": subject,
        "accountPurpose": purpose,
        "sessionVersion": version,
        "csrfHash": value["csrfHash"],
        "roles": tuple(roles),
    }


def _validate_current_user(
    value: Any,
    *,
    scope: Mapping[str, str],
    expected_subject: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _reject()
    purpose = value.get("accountPurpose")
    if (
        value.get("pk") != THN_CURRENT_USER_PARTITION_KEY
        or value.get("sk") != f"SUBJECT#{expected_subject}"
        or value.get("contractVersion") != 1
        or value.get("scope") != scope
        or value.get("subject") != expected_subject
        or purpose not in ALLOWED_ACCOUNT_PURPOSES
        or value.get("enabled") is not True
    ):
        _reject()
    return {
        "accountPurpose": purpose,
        "sessionVersion": _positive_integer(value.get("sessionVersion")),
    }


def load_authorization_context(
    store: Any,
    *,
    session_id_hash: str,
    registry_record: Mapping[str, Any],
    now_epoch: int,
) -> AuthorizationContext:
    """Strongly reload the session and current user before protected access."""

    if (
        not isinstance(session_id_hash, str)
        or not _HASH_RE.fullmatch(session_id_hash)
        or type(now_epoch) is not int
        or now_epoch < 0
    ):
        _reject()
    scope, writer_mode, writer_epoch = _validated_registry_scope(registry_record)
    try:
        raw_session = store.get_session(session_id_hash, consistent_read=True)
    except Exception:
        _reject()
    session = _validate_session(
        raw_session,
        scope=scope,
        expected_session_id_hash=session_id_hash,
        now_epoch=now_epoch,
    )
    try:
        raw_user = store.get_current_user(
            session["subject"],
            consistent_read=True,
        )
    except Exception:
        _reject()
    user = _validate_current_user(
        raw_user,
        scope=scope,
        expected_subject=session["subject"],
    )
    if (
        session["accountPurpose"] != user["accountPurpose"]
        or session["sessionVersion"] != user["sessionVersion"]
    ):
        _reject()

    return AuthorizationContext(
        subject=session["subject"],
        account_purpose=user["accountPurpose"],
        session_version=user["sessionVersion"],
        csrf_hash=session["csrfHash"],
        roles=session["roles"],
        writer_mode=writer_mode,
        writer_epoch=writer_epoch,
        environment=scope["environment"],
        domain=scope["domain"],
        service_binding_id=scope["serviceBindingId"],
        auth_profile_id=scope["authProfileId"],
        tenant_id=scope["tenantId"],
        hub_id=scope["hubId"],
    )


def assert_record_purpose_visible(
    context: AuthorizationContext,
    record: Mapping[str, Any],
) -> None:
    if not isinstance(record, Mapping):
        _reject()
    expected_scope = {
        "environment": context.environment,
        "domain": context.domain,
        "serviceBindingId": context.service_binding_id,
        "authProfileId": context.auth_profile_id,
        "tenantId": context.tenant_id,
        "hubId": context.hub_id,
    }
    _require_record_scope(record, expected_scope)
    record_purpose = record.get("recordPurpose")
    if record_purpose not in ALLOWED_ACCOUNT_PURPOSES:
        _reject()
    if record_purpose != context.account_purpose:
        _not_found()


def _revalidate_context(
    context: AuthorizationContext,
    *,
    store: Any,
    session_id_hash: str,
    current_registry_record: Mapping[str, Any],
    now_epoch: int,
) -> AuthorizationContext:
    fresh = load_authorization_context(
        store,
        session_id_hash=session_id_hash,
        registry_record=current_registry_record,
        now_epoch=now_epoch,
    )
    if fresh != context:
        _reject()
    return fresh


def _assert_record_identity(record: Mapping[str, Any], record_id: Any) -> None:
    if (
        not isinstance(record_id, str)
        or not _SAFE_RECORD_ID_RE.fullmatch(record_id)
        or record.get("articleId") != record_id
    ):
        _not_found()


def authorize_final_read(
    context: AuthorizationContext,
    *,
    store: Any,
    session_id_hash: str,
    current_registry_record: Mapping[str, Any],
    now_epoch: int,
    operation: str,
    record: Mapping[str, Any] | None = None,
    records: Iterable[Mapping[str, Any]] | None = None,
    record_id: str | None = None,
) -> Any:
    """Apply purpose isolation immediately before returning private data."""

    context = _revalidate_context(
        context,
        store=store,
        session_id_hash=session_id_hash,
        current_registry_record=current_registry_record,
        now_epoch=now_epoch,
    )
    if operation in _LIST_READ_OPERATIONS:
        if (
            record is not None
            or record_id is not None
            or records is None
            or isinstance(records, (str, bytes, Mapping))
        ):
            _reject()
        visible = []
        for candidate in records:
            if not isinstance(candidate, Mapping):
                _reject()
            expected_scope = {
                "environment": context.environment,
                "domain": context.domain,
                "serviceBindingId": context.service_binding_id,
                "authProfileId": context.auth_profile_id,
                "tenantId": context.tenant_id,
                "hubId": context.hub_id,
            }
            _require_record_scope(candidate, expected_scope)
            purpose = candidate.get("recordPurpose")
            if purpose not in ALLOWED_ACCOUNT_PURPOSES:
                _reject()
            if purpose == context.account_purpose:
                visible.append(deepcopy(dict(candidate)))
        return visible
    if operation in _REFERENCE_READ_OPERATIONS:
        if (
            record is not None
            or record_id is not None
            or records is None
            or isinstance(records, (str, bytes, Mapping))
        ):
            _reject()
        references = []
        for candidate in records:
            if not isinstance(candidate, Mapping):
                _reject()
            references.append(deepcopy(dict(candidate)))
        return references
    if operation in _DIRECT_READ_OPERATIONS:
        if records is not None or record is None:
            _reject()
        assert_record_purpose_visible(context, record)
        _assert_record_identity(record, record_id)
        return deepcopy(dict(record))
    _reject()


def _writer_mode_allows(context: AuthorizationContext) -> bool:
    return (
        context.writer_mode == "qa-only"
        and context.account_purpose == "qa"
    ) or (
        context.writer_mode == "client-owner"
        and context.account_purpose == "client-owner"
    )


def assert_mutation_actor_enabled(context: AuthorizationContext) -> None:
    """Reject all user mutations unless purpose and current writer mode agree."""

    if not _writer_mode_allows(context):
        raise ContentHubV2WriterDisabledError(
            "authoring mutations are unavailable"
        ) from None


def authorize_mutation(
    context: AuthorizationContext,
    *,
    store: Any,
    session_id_hash: str,
    current_registry_record: Mapping[str, Any],
    now_epoch: int,
    operation: str,
    record: Mapping[str, Any] | None = None,
    record_id: str | None = None,
) -> str | None:
    """Authorize a v2 mutation and derive its server-owned record purpose."""

    context = _revalidate_context(
        context,
        store=store,
        session_id_hash=session_id_hash,
        current_registry_record=current_registry_record,
        now_epoch=now_epoch,
    )
    assert_mutation_actor_enabled(context)
    if operation == _CREATE_OPERATION:
        if record is not None or record_id is not None:
            _reject()
        return context.account_purpose
    if operation in _RECORD_MUTATION_OPERATIONS:
        if record is None:
            _reject()
        assert_record_purpose_visible(context, record)
        _assert_record_identity(record, record_id)
        return None
    _reject()


def assert_writer_epoch_current(
    context: AuthorizationContext,
    current_registry_record: Mapping[str, Any],
) -> None:
    """Reject a stale purpose/mode context before the final read or mutation."""

    scope, writer_mode, writer_epoch = _validated_registry_scope(current_registry_record)
    expected = {
        "environment": context.environment,
        "domain": context.domain,
        "serviceBindingId": context.service_binding_id,
        "authProfileId": context.auth_profile_id,
        "tenantId": context.tenant_id,
        "hubId": context.hub_id,
    }
    if (
        scope != expected
        or writer_mode != context.writer_mode
        or writer_epoch != context.writer_epoch
    ):
        _reject()


__all__ = [
    "ALLOWED_ACCOUNT_PURPOSES",
    "AuthorizationContext",
    "ContentHubV2AuthorizationError",
    "ContentHubV2NotFoundError",
    "ContentHubV2WriterDisabledError",
    "THN_CURRENT_USER_SCOPE",
    "assert_record_purpose_visible",
    "assert_mutation_actor_enabled",
    "assert_writer_epoch_current",
    "authorize_final_read",
    "authorize_mutation",
    "load_authorization_context",
]
