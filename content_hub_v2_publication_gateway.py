"""Private authoring-to-publisher invocation; never writes public state."""
import json
import re
import time
from content_hub_v2_authorization import (
    THN_CURRENT_USER_SCOPE, assert_mutation_actor_enabled, assert_record_purpose_visible,
    ContentHubV2AuthorizationError,
)
from content_hub_v2_editor_model import EditorValidationError
from content_hub_v2_editor_model import EditorConflict
from content_hub_v2_publication_contract import PUBLISHER_NAME, validate_envelope, validate_result


class PublicationGateway:
    def __init__(self, auth, session_hash, scope, binding, *, clock=None, lambda_client=None):
        expected=f"arn:{scope['partition']}:lambda:{scope['region']}:{scope['accountId']}:function:{PUBLISHER_NAME}:test"
        if not binding or binding!=expected:
            raise EditorValidationError('feature_not_ready')
        self.auth,self.session_hash,self.binding=auth,session_hash,binding
        self.clock,self.client=clock or (lambda:int(time.time())),lambda_client

    def __call__(self, operation, record, locale, authorize, data):
        assert_mutation_actor_enabled(self.auth); assert_record_purpose_visible(self.auth,record)
        action='unpublish' if operation=='unpublishArticle' else operation
        envelope={**THN_CURRENT_USER_SCOPE,'schemaVersion':1,'source':'thn-authoring-v2','operation':action,
            'articleId':record['articleId'],'locale':locale,'revisionId':data.get('revisionId','') if action=='publish' else '',
            'expectedToken':data.get('concurrencyToken'),'operationId':data.get('idempotencyKey'),
            'actorSubject':self.auth.subject,'actorPurpose':self.auth.account_purpose,'sessionVersion':self.auth.session_version,
            'sessionIdHash':self.session_hash,'writerMode':self.auth.writer_mode,'writerEpoch':self.auth.writer_epoch,
            'issuedAtEpoch':self.clock()}
        validate_envelope(envelope,self.clock())
        authorize()
        if self.client is None:
            import boto3
            from botocore.config import Config
            self.client=boto3.client('lambda',config=Config(read_timeout=115,retries={'max_attempts':0}))
        response=self.client.invoke(FunctionName=self.binding,InvocationType='RequestResponse',
            Payload=json.dumps(envelope,separators=(',',':')).encode())
        if response.get('FunctionError') or response.get('StatusCode')!=200:
            raise EditorValidationError('publication_unavailable')
        try: raw=response['Payload'].read(4097)
        finally: response['Payload'].close()
        if len(raw)>4096: raise EditorValidationError('publication_unavailable')
        try: result=json.loads(raw)
        except (ValueError,TypeError): raise EditorValidationError('publication_unavailable') from None
        authorize()
        if not isinstance(result,dict): raise EditorValidationError('publication_unavailable')
        if result.get('ok') is not True:
            if set(result)!={'ok','code'}: raise EditorValidationError('publication_unavailable')
            if result.get('code')=='edit_conflict': raise EditorConflict()
            if result.get('code')=='auth_required': raise ContentHubV2AuthorizationError()
            raise EditorValidationError('publication_unavailable')
        if set(result)!={'ok','data'}: raise EditorValidationError('publication_unavailable')
        return validate_result(result['data'],record['articleId'],locale,action)
