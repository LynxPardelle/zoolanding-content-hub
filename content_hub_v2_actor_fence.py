"""Pure final-transaction actor checks shared by THN private/public writers.

No session read, SDK client, cookie, or request-handler dependency. The publisher
may only check its captured session within the same transaction as publication.
"""
import re
from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE
from content_hub_v2_editor_model import EditorValidationError
from content_hub_v2_registry_fence import marshal_item

USER_TABLE = "zoolanding-auth-admin-test-ThnCurrentUserStateV2"
SESSION_TABLE = "zoolanding-auth-admin-test-ThnSessionV2"
SCOPE_ATTRIBUTES = {"environment":"environment","domain":"domain","serviceBindingId":"service_binding_id",
                    "authProfileId":"auth_profile_id","tenantId":"tenant_id","hubId":"hub_id"}


def actor_condition_checks(auth, session_hash, now):
    """No returned session data, including on a conditional failure."""
    if (not isinstance(session_hash,str) or re.fullmatch(r"[a-f0-9]{64}",session_hash) is None
            or type(now) is not int or now < 0
            or not isinstance(getattr(auth,"subject",None),str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",auth.subject) is None
            or getattr(auth,"account_purpose",None) not in {"qa","client-owner"}
            or type(getattr(auth,"session_version",None)) is not int or auth.session_version < 1
            or any(getattr(auth,attribute,None)!=THN_CURRENT_USER_SCOPE[key] for key,attribute in SCOPE_ATTRIBUTES.items())):
        raise EditorValidationError("invalid_publication_authority")
    common = {":purpose": auth.account_purpose, ":version": auth.session_version,
              ":subject": auth.subject, ":scope": dict(THN_CURRENT_USER_SCOPE)}
    return [{"ConditionCheck": {
        "TableName": USER_TABLE,
        "Key": marshal_item({"pk": "CURRENT_USER#test#thn-journal-test-v2", "sk": f"SUBJECT#{auth.subject}"}),
        "ConditionExpression": "enabled = :enabled AND #purpose = :purpose AND #version = :version AND #subject = :subject AND #scope = :scope",
        "ExpressionAttributeNames": {"#purpose": "accountPurpose", "#version": "sessionVersion", "#subject": "subject", "#scope": "scope"},
        "ExpressionAttributeValues": marshal_item({**common, ":enabled": True}),
    }}, {"ConditionCheck": {
        "TableName": SESSION_TABLE, "Key": marshal_item({"sessionIdHash": session_hash}),
        "ConditionExpression": "#purpose = :purpose AND #version = :version AND #subject = :subject AND #scope = :scope AND idleExpiresAt > :now AND absoluteExpiresAt > :now AND (attribute_not_exists(revokedAt) OR attribute_type(revokedAt, :nullType))",
        "ExpressionAttributeNames": {"#purpose": "accountPurpose", "#version": "sessionVersion", "#subject": "subject", "#scope": "scope"},
        "ExpressionAttributeValues": marshal_item({**common, ":now": now, ":nullType": "NULL"}),
    }}]
