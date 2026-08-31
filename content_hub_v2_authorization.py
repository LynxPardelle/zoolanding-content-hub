"""Dormant fail-closed authorization contract for THN Content Hub v2.

TASK-011 defines purpose and session-version semantics only.  The dedicated
v2 handler and IAM identities are added by later tasks; the shared v1 handler
must not import this module.
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

_LIST_READ_OPERATIONS = frozenset({"articleList", "assetList"})
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


@dataclass(frozen=True)
class AuthorizationContext:
    subject: str
    scope_key: str
    account_purpose: str
    session_version: int
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


def _scope_key(scope: Mapping[str, str]) -> str:
    return "CURRENT_USER#" + "#".join(
        (
            scope["environment"],
            scope["domain"],
            scope["serviceBindingId"],
            scope["authProfileId"],
            scope["tenantId"],
            scope["hubId"],
        )
    )


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
    expected_scope_key: str,
    now_epoch: int,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _reject()
    _require_record_scope(value, scope)
    subject = value.get("subject")
    purpose = value.get("accountPurpose")
    if (
        value.get("scopeKey") != expected_scope_key
        or not isinstance(subject, str)
        or not _SAFE_SUBJECT_RE.fullmatch(subject)
        or purpose not in ALLOWED_ACCOUNT_PURPOSES
        or value.get("revoked") is not False
        or _positive_integer(value.get("expiresAt")) <= now_epoch
    ):
        _reject()
    version = _positive_integer(value.get("sessionVersion"))
    return {
        "subject": subject,
        "accountPurpose": purpose,
        "sessionVersion": version,
    }


def _validate_current_user(
    value: Any,
    *,
    scope: Mapping[str, str],
    expected_scope_key: str,
    expected_subject: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _reject()
    _require_record_scope(value, scope)
    purpose = value.get("accountPurpose")
    if (
        value.get("recordType") != "thn-current-user-v2"
        or value.get("scopeKey") != expected_scope_key
        or value.get("userKey") != f"USER#{expected_subject}"
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
    expected_scope_key = _scope_key(scope)
    try:
        raw_session = store.get_session(session_id_hash, consistent_read=True)
    except Exception:
        _reject()
    session = _validate_session(
        raw_session,
        scope=scope,
        expected_scope_key=expected_scope_key,
        now_epoch=now_epoch,
    )
    try:
        raw_user = store.get_current_user(
            expected_scope_key,
            f"USER#{session['subject']}",
            consistent_read=True,
        )
    except Exception:
        _reject()
    user = _validate_current_user(
        raw_user,
        scope=scope,
        expected_scope_key=expected_scope_key,
        expected_subject=session["subject"],
    )
    if (
        session["accountPurpose"] != user["accountPurpose"]
        or session["sessionVersion"] != user["sessionVersion"]
    ):
        _reject()

    return AuthorizationContext(
        subject=session["subject"],
        scope_key=expected_scope_key,
        account_purpose=user["accountPurpose"],
        session_version=user["sessionVersion"],
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
    if not _writer_mode_allows(context):
        _reject()
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
    "THN_CURRENT_USER_SCOPE",
    "assert_record_purpose_visible",
    "assert_writer_epoch_current",
    "authorize_final_read",
    "authorize_mutation",
    "load_authorization_context",
]
