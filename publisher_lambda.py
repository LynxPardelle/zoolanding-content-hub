"""IAM-invoked THN publisher, physically separate from browser authoring.

No event-supplied storage binding, cookie, HTML or session read is accepted.
The exact TEST alias and immutable server configuration are mandatory. Deployment
and registry/writer activation remain independent, fail-closed release controls.
"""
import os
import re
import time
from types import SimpleNamespace
from content_hub_v2_authorization import (
    THN_CURRENT_USER_SCOPE, _validate_current_user, ContentHubV2AuthorizationError,
)
from content_hub_v2_actor_fence import actor_condition_checks, SCOPE_ATTRIBUTES, USER_TABLE
from content_hub_v2_registry_fence import _condition_check, marshal_item, unmarshal_item
from content_hub_v2_state_keys import METADATA_TABLE, ARTICLE_PK, PARTITION_PREFIX, PRIVATE_PREFIX
from content_hub_v2_editor_model import EditorValidationError, normalize_package, referenced_assets, MAX_PACKAGE_BYTES
from content_hub_v2_editor_model import EditorConflict
from content_hub_v2_finalization import AwsPublicationStore, OPERATION_PK
from content_hub_v2_preparation import prepare_immutable_objects, _bytes, _sha
from content_hub_v2_projection_store import PARTITION as PREPARATION_PK
from content_hub_v2_publication_contract import PUBLISHER_NAME, validate_envelope, validate_result
from service_binding_registry_consumer_v2 import load_active_service_binding


class HandlerNotActiveError(RuntimeError):
    """The exact internal request/runtime cannot safely be selected."""


class PublicationRuntime:
    def __init__(self, context, configuration, *, dynamodb=None, s3=None, clock=None):
        arn=getattr(context,'invoked_function_arn','')
        match=re.fullmatch(r'arn:(aws):lambda:([a-z]{2}(?:-[a-z]+)+-[0-9]):([0-9]{12}):function:'
            +re.escape(PUBLISHER_NAME)+r':test',arn) if isinstance(arn,str) else None
        if not match: raise HandlerNotActiveError('publication unavailable')
        self.scope=dict(zip(('partition','region','accountId'),match.groups()))
        self.config=dict(configuration)
        required={'CONTENT_HUB_ENVIRONMENT':'test','CONTENT_HUB_DOMAIN':'thehairnarrative.com',
            'CONTENT_HUB_ID':'thehairnarrative-com-journal','THN_CONTENT_HUB_METADATA_TABLE_NAME':METADATA_TABLE,
            'THN_CONTENT_HUB_PRIVATE_BUCKET_NAME':f"zlp-thn-ch-test-private-{self.scope['accountId']}-{self.scope['region']}"}
        if any(self.config.get(k)!=v for k,v in required.items()): raise HandlerNotActiveError('publication unavailable')
        self.descriptor={key:self.config.get(env,'') for key,env in (
            ('descriptorVersionId','THN_CONTENT_HUB_DESCRIPTOR_VERSION_ID'),
            ('descriptorSha256','THN_CONTENT_HUB_DESCRIPTOR_SHA256'),
            ('authPolicyVersion','THN_CONTENT_HUB_AUTH_POLICY_VERSION'))}
        for key,value in self.descriptor.items():
            pattern=r'[a-f0-9]{64}' if key=='descriptorSha256' else r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}'
            if not isinstance(value,str) or re.fullmatch(pattern,value) is None or value in ('BLOCKED','0'*64):
                raise HandlerNotActiveError('publication unavailable')
        if not self.config.get('CONTENT_HUB_METADATA_TABLE_NAME') or not self.config.get('CONTENT_HUB_PACKAGES_BUCKET_NAME'):
            raise HandlerNotActiveError('publication unavailable')
        self._ddb,self._s3,self.clock=dynamodb,s3,clock or (lambda:int(time.time()))

    def clients(self):
        if self._ddb is None or self._s3 is None:
            import boto3
            if self._ddb is None: self._ddb=boto3.client('dynamodb')
            if self._s3 is None: self._s3=boto3.client('s3')
        return self._ddb,self._s3

    def get(self, table, key):
        row=self._ddb.get_item(TableName=table,Key=marshal_item(key),ConsistentRead=True).get('Item')
        return unmarshal_item(row) if row else None

    def guards(self, envelope):
        validate_envelope(envelope,self.clock())
        record=load_active_service_binding(self._ddb,expected_descriptor=self.descriptor,trusted_resource_scope=self.scope)
        if record['writerEpoch']!=envelope['writerEpoch'] or record['writerMode']!=envelope['writerMode']:
            raise ContentHubV2AuthorizationError()
        user=_validate_current_user(self.get(USER_TABLE,{'pk':'CURRENT_USER#test#thn-journal-test-v2',
            'sk':'SUBJECT#'+envelope['actorSubject']}),scope=THN_CURRENT_USER_SCOPE,expected_subject=envelope['actorSubject'])
        if user['accountPurpose']!=envelope['actorPurpose'] or user['sessionVersion']!=envelope['sessionVersion']:
            raise ContentHubV2AuthorizationError()
        actor=SimpleNamespace(subject=envelope['actorSubject'],account_purpose=user['accountPurpose'],
            session_version=user['sessionVersion'],**{v:THN_CURRENT_USER_SCOPE[k] for k,v in SCOPE_ATTRIBUTES.items()})
        return [_condition_check(record),*actor_condition_checks(actor,envelope['sessionIdHash'],self.clock())]

    def execute(self, envelope):
        ddb,s3=self.clients()
        authorize=lambda:self.guards(envelope)
        authorize()
        store=AwsPublicationStore(dynamodb=ddb,s3=s3,account_id=self.scope['accountId'],region=self.scope['region'],
            private_bucket=self.config['THN_CONTENT_HUB_PRIVATE_BUCKET_NAME'],
            source_bucket=f"zlp-thn-private-upload-test-{self.scope['accountId']}-{self.scope['region']}",
            delivery_bucket=self.config['CONTENT_HUB_PACKAGES_BUCKET_NAME'],
            public_table=self.config['CONTENT_HUB_METADATA_TABLE_NAME'],guard_factory=authorize)
        article,locale,revision=envelope['articleId'],envelope['locale'],envelope['revisionId']
        params=dict(article_id=article,locale=locale,expected_token=envelope['expectedToken'],operation_id=envelope['operationId'])
        if envelope['operation']=='unpublish': return store.finalize_unpublish_transaction(**params)
        receipt=self.get(METADATA_TABLE,{'pk':OPERATION_PK,'sk':'OPERATION#'+envelope['operationId']})
        if receipt is None:
            allocation=store.allocate_publication(article_id=article,locale=locale,revision_id=revision,
                expected_token=envelope['expectedToken'])
            row=self.get(METADATA_TABLE,{'pk':ARTICLE_PK,'sk':'ARTICLE#'+article})
            if (not row or row.get('recordPurpose')!=envelope['actorPurpose'] or row.get('concurrencyToken')!=envelope['expectedToken']
                    or row.get('locales',{}).get(locale,{}).get('workingRevisionId')!=revision): raise EditorConflict()
            prep=self.get(METADATA_TABLE,{'pk':PREPARATION_PK,'sk':'PREPARATION#prep-'+_sha(_bytes([article,locale,revision]))})
            if prep is None or (prep.get('state')=='preparing'
                    and len(prep.get('receipts',{}))!=len(prep.get('intent',{}).get('objects',[]))):
                pointer=row['locales'][locale]['packagePointer']
                if pointer.get('key')!=PRIVATE_PREFIX+f'immutable-revisions/{article}/{locale}/{revision}/package.json':
                    raise EditorValidationError('invalid_package_pointer')
                package=normalize_package({**store._json(store.private_bucket,pointer,MAX_PACKAGE_BYTES),'seriesId':row['seriesId']})
                assets={asset:self.get(METADATA_TABLE,{'pk':PARTITION_PREFIX+f'ASSETS#{article}#{locale}','sk':'ASSET#'+asset})
                    for asset in referenced_assets(package)}
                prepare_immutable_objects(article_id=article,locale=locale,revision_id=revision,package=package,assets=assets,
                    path=allocation['path'],first_published_at=allocation['firstPublishedAt'],updated_at=allocation['updatedAt'],
                    purpose=envelope['actorPurpose'],now_epoch=self.clock(),store=store,authorize=authorize)
        return store.finalize_publication_transaction(**params,revision_id=revision)


def handle_publication(event, *, runtime):
    try:
        envelope=validate_envelope(event,runtime.clock())
        result=runtime.execute(envelope)
        return {'ok':True,'data':validate_result(result,envelope['articleId'],envelope['locale'],envelope['operation'])}
    except EditorConflict:
        return {'ok':False,'code':'edit_conflict'}
    except ContentHubV2AuthorizationError:
        return {'ok':False,'code':'auth_required'}
    except Exception:
        return {'ok':False,'code':'publication_unavailable'}


def lambda_handler(event, context):
    try: validate_envelope(event,int(time.time()))
    except Exception: raise HandlerNotActiveError('publication unavailable') from None
    runtime=PublicationRuntime(context,os.environ)
    return handle_publication(event,runtime=runtime)
