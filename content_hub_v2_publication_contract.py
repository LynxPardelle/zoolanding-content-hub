"""Closed internal publication envelope. No HTTP, credentials or SDK clients."""
import re
from copy import deepcopy
from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE
from content_hub_v2_editor_model import EditorValidationError, safe_id, safe_locale

PUBLISHER_NAME = 'zoolanding-content-hub-test-ThnV2Publisher'
ENVELOPE_FIELDS = set(THN_CURRENT_USER_SCOPE) | {
    'schemaVersion','source','operation','articleId','locale','revisionId','expectedToken',
    'operationId','actorSubject','actorPurpose','sessionVersion','sessionIdHash',
    'writerMode','writerEpoch','issuedAtEpoch',
}


def validate_envelope(value, now):
    if (not isinstance(value,dict) or set(value)!=ENVELOPE_FIELDS
            or any(value.get(k)!=v for k,v in THN_CURRENT_USER_SCOPE.items())
            or type(value.get('schemaVersion')) is not int or value['schemaVersion']!=1
            or value.get('source')!='thn-authoring-v2' or value.get('operation') not in {'publish','unpublish'}
            or value.get('actorPurpose') not in {'qa','client-owner'}
            or value.get('writerMode')!={'qa':'qa-only','client-owner':'client-owner'}[value['actorPurpose']]
            or any(type(value.get(k)) is not int or value[k]<1 for k in ('sessionVersion','writerEpoch'))
            or type(now) is not int or type(value.get('issuedAtEpoch')) is not int
            or not now-120<=value['issuedAtEpoch']<=now
            or not isinstance(value.get('sessionIdHash'),str) or re.fullmatch(r'[a-f0-9]{64}',value['sessionIdHash']) is None
            or not isinstance(value.get('operationId'),str) or re.fullmatch(r'[a-f0-9]{32}',value['operationId']) is None
            or not isinstance(value.get('actorSubject'),str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}',value['actorSubject']) is None):
        raise EditorValidationError('invalid_publication_request')
    safe_id(value['articleId']); safe_locale(value['locale']); safe_id(value['expectedToken'])
    if value['operation']=='publish': safe_id(value['revisionId'])
    elif value['revisionId']!='': raise EditorValidationError('invalid_publication_request')
    return deepcopy(value)


def validate_result(value, article_id, locale, operation):
    if (not isinstance(value,dict) or set(value)!={'articleId','locale','state','concurrencyToken'}
            or value.get('articleId')!=article_id or value.get('locale')!=locale
            or value.get('state')!={'publish':'published','unpublish':'unpublished'}[operation]):
        raise EditorValidationError('publication_unavailable')
    safe_id(value['concurrencyToken'])
    return deepcopy(value)
