"""Exact-candidate THN cleanup with a conditional claim and a quiet period.

Never discovers/list objects. A claim excludes the publisher's final transaction;
the five-minute grace exceeds the publisher's maximum invocation time, including
any immutable write already in flight. Later calls verify every exact key/digest
before deleting pinned versions. Disabled by default, operator-supplied IDs only.
"""
from copy import deepcopy
from types import SimpleNamespace
import json
import os
import re
import time

from content_hub_v2_projection_store import AwsPreparationStore, PARTITION, METADATA_TABLE
from content_hub_v2_projection import bundle_key
from content_hub_v2_preparation import _bytes, _sha, _version, MAX_OBJECT_BYTES
from content_hub_v2_state_keys import ARTICLE_PK
from content_hub_v2_projection_manifest import MANIFEST_PK, validate_projection_page
from content_hub_v2_registry_fence import _condition_check, marshal_item, unmarshal_item
from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE
from service_binding_registry_consumer_v2 import load_active_service_binding

FUNCTION_NAME='zoolanding-content-hub-test-ThnV2PreparedOrphanCollector'
MIN_AGE_SECONDS=30*86400
QUIET_PERIOD_SECONDS=300


class CollectionError(RuntimeError): pass
class HandlerNotActiveError(CollectionError): pass
def _reject(): raise CollectionError('collection_unavailable')


def _condition(table,key,row):
    value={'TableName':table,'Key':marshal_item(key)}
    if row is None:
        return {**value,'ConditionExpression':'attribute_not_exists(#pk)','ExpressionAttributeNames':{'#pk':'pk'}}
    fields=sorted(row)
    return {**value,'ConditionExpression':' AND '.join(f'#f{i} = :v{i}' for i in range(len(fields))),
        'ExpressionAttributeNames':{f'#f{i}':name for i,name in enumerate(fields)},
        'ExpressionAttributeValues':marshal_item({f':v{i}':row[name] for i,name in enumerate(fields)})}


class PreparedOrphanRuntime:
    def __init__(self,*,dynamodb,s3,table,public_table,bucket,registry_guard,clock=None):
        if (table!=METADATA_TABLE or not isinstance(public_table,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{3,255}',public_table)
            or public_table==table or 'Thn' in public_table or not isinstance(bucket,str)
            or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',bucket) or 'private-upload' in bucket or '-private-' in bucket
            or not callable(registry_guard)): _reject()
        self.ddb,self.s3,self.table,self.public_table,self.bucket=dynamodb,s3,table,public_table,bucket
        self.registry_guard,self.clock=registry_guard,clock or time.time

    def read(self,table,key):
        result=self.ddb.get_item(TableName=table,Key=marshal_item(key),ConsistentRead=True)
        row=unmarshal_item(result['Item']) if result.get('Item') else None
        if row is not None and any(row.get(k)!=v for k,v in key.items()): _reject()
        return row

    def objects(self,intent,receipts,*,resuming):
        expected={s['key']:s for s in intent['objects']};found=[];path=None
        for oid,receipt in receipts.items():
            AwsPreparationStore._receipt(SimpleNamespace(expected=expected),receipt)
            if oid!=_sha(receipt['key'].encode()): _reject()
        for spec in intent['objects']:
            receipt=receipts.get(_sha(spec['key'].encode()))
            args={'Bucket':self.bucket,'Key':spec['key']}
            if receipt: args['VersionId']=receipt['versionId']
            try: response=self.s3.get_object(**args)
            except Exception as error:
                code=getattr(error,'response',{}).get('Error',{}).get('Code')
                if code in {'NoSuchKey','NoSuchVersion'} and (resuming or not receipt): continue
                _reject()
            try: body=response['Body'].read(MAX_OBJECT_BYTES+1)
            finally: response['Body'].close()
            if (not isinstance(body,bytes) or len(body)!=spec['bytes'] or _sha(body)!=spec['sha256']
                or response.get('ContentType')!=spec['contentType'] or response.get('ContentLength')!=spec['bytes']): _reject()
            version=_version(response.get('VersionId'))
            if receipt and receipt['versionId']!=version: _reject()
            found.append({**spec,'versionId':version})
            if spec['key']==bundle_key(intent['articleId'],intent['locale'],intent['revisionId']):
                bundle=json.loads(body);path=bundle.get('path')
                if (bundle.get('articleId')!=intent['articleId'] or bundle.get('locale')!=intent['locale']
                    or not isinstance(path,str) or not re.fullmatch(r'/the-journal/[a-z0-9-]+/[a-z0-9-]+',path)): _reject()
        return found,path

    def fence(self,row,path):
        intent=row['intent'];article,locale,revision=(intent[k] for k in ('articleId','locale','revisionId'))
        keys=[(self.table,{'pk':ARTICLE_PK,'sk':'ARTICLE#'+article}),
            (self.table,{'pk':MANIFEST_PK,'sk':'PAGE#'+article}),
            (self.public_table,{'pk':'HUB#thehairnarrative-com-journal','sk':'ARTICLE#'+article}),
            (self.public_table,{'pk':f'LIVE_MEDIA#test#thehairnarrative.com#thehairnarrative-com-journal#{article}#{locale}#{revision}','sk':'MANIFEST#V1'}),
            (self.public_table,{'pk':'SLUG#test#thehairnarrative.com#'+locale,'sk':'PATH#'+path})]
        conditions=[]
        for index,(table,key) in enumerate(keys):
            current=self.read(table,key)
            if current:
                if index==0:
                    if any(current.get(k)!=v for k,v in THN_CURRENT_USER_SCOPE.items()): _reject()
                    state=current.get('locales',{}).get(locale,{})
                    if revision in {state.get('workingRevisionId'),state.get('publishedRevisionId')}: return None
                elif index==1:
                    page=validate_projection_page(current)
                    if any(p.get('articleId')==article and p.get('locale')==locale and p.get('revisionId')==revision for p in page['livePointers']): return None
                elif index==3: return None
                else:
                    material=json.dumps(current,sort_keys=True)
                    if bundle_key(article,locale,revision) in material or f'/public-media/{article}/{locale}/{revision}/' in material: return None
            conditions.append({'ConditionCheck':_condition(table,key,current)})
        return conditions

    def commit(self,before,after,fences):
        guard=self.registry_guard()
        values=unmarshal_item(guard['ConditionCheck']['ExpressionAttributeValues'])
        registry={k[1:]:v for k,v in values.items()}
        if guard!=_condition_check(registry) or any(registry.get(k)!=v for k,v in THN_CURRENT_USER_SCOPE.items()): _reject()
        put=_condition(self.table,{k:before[k] for k in ('pk','sk')},before)
        put.pop('Key');put['Item']=marshal_item(after)
        self.ddb.transact_write_items(TransactItems=[guard,*fences,{'Put':put}])


def collect_prepared_candidate(preparation_id,*,runtime):
    if not isinstance(preparation_id,str) or not re.fullmatch(r'prep-[a-f0-9]{64}',preparation_id): _reject()
    try:
        row=runtime.read(runtime.table,{'pk':PARTITION,'sk':'PREPARATION#'+preparation_id})
        if not row: return {'state':'absent'}
        if set(row)-{'pk','sk','intent','state','receipts','collection'} or not isinstance(row.get('receipts'),dict): _reject()
        intent=AwsPreparationStore._validate_intent(row['intent'])
        if intent['preparationId']!=preparation_id: _reject()
        now=int(runtime.clock())
        if row['state']=='live' or intent['candidateAtEpoch']>now-MIN_AGE_SECONDS: return {'state':'retained'}
        if row['state'] not in {'preparing','retired','collecting','collected'}: _reject()
        collection=row.get('collection')
        resuming=row['state'] in {'collecting','collected'}
        if resuming:
            if (not isinstance(collection,dict) or set(collection)!={'claimedAtEpoch','path'}
                or type(collection['claimedAtEpoch']) is not int or not intent['candidateAtEpoch']+MIN_AGE_SECONDS<=collection['claimedAtEpoch']<=now
                or not isinstance(collection['path'],str) or not re.fullmatch(r'/the-journal/[a-z0-9-]+/[a-z0-9-]+',collection['path'])): _reject()
            if row['state']=='collected': return {'state':'collected'}
            if now<collection['claimedAtEpoch']+QUIET_PERIOD_SECONDS: return {'state':'collecting'}
        elif collection is not None: _reject()
        objects,path=runtime.objects(intent,row['receipts'],resuming=resuming)
        path=collection['path'] if resuming else path
        if not path: return {'state':'retained'}
        fences=runtime.fence(row,path)
        if fences is None: return {'state':'retained'}
        if not resuming:
            runtime.commit(row,{**row,'state':'collecting','collection':{'claimedAtEpoch':now,'path':path}},fences)
            return {'state':'collecting'}
        # Revalidate the fence before deletion, still conditionally holding the
        # collecting state. No publisher can turn a collecting candidate live.
        runtime.commit(row,row,fences)
        for receipt in objects:
            runtime.s3.delete_object(Bucket=runtime.bucket,Key=receipt['key'],VersionId=receipt['versionId'])
        runtime.commit(row,{**row,'state':'collected'},fences)
        return {'state':'collected'}
    except CollectionError: raise
    except Exception: raise CollectionError('collection_retry_required') from None


def lambda_handler(event,context):
    if (not isinstance(event,dict) or set(event)!={'schemaVersion','source','preparationId'}
        or type(event.get('schemaVersion')) is not int or event['schemaVersion']!=1 or event['source']!='thn-prepared-orphans'
        or not isinstance(event.get('preparationId'),str) or not re.fullmatch(r'prep-[a-f0-9]{64}',event['preparationId'])):
        raise HandlerNotActiveError('collection_not_active')
    arn=getattr(context,'invoked_function_arn','')
    match=re.fullmatch(r'arn:(aws):lambda:([a-z]{2}(?:-[a-z]+)+-[0-9]):([0-9]{12}):function:'+FUNCTION_NAME+':test',arn) if isinstance(arn,str) else None
    if not match: raise HandlerNotActiveError('collection_not_active')
    scope=dict(zip(('partition','region','accountId'),match.groups()))
    descriptor={key:os.environ.get(env,'') for key,env in (
        ('descriptorVersionId','THN_CONTENT_HUB_DESCRIPTOR_VERSION_ID'),('descriptorSha256','THN_CONTENT_HUB_DESCRIPTOR_SHA256'),
        ('authPolicyVersion','THN_CONTENT_HUB_AUTH_POLICY_VERSION'))}
    for key,value in descriptor.items():
        if not re.fullmatch(r'[a-f0-9]{64}' if key=='descriptorSha256' else r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}',value) or value in {'BLOCKED','0'*64}: raise HandlerNotActiveError('collection_not_active')
    config={'table':os.environ.get('THN_CONTENT_HUB_METADATA_TABLE_NAME'),'public_table':os.environ.get('CONTENT_HUB_METADATA_TABLE_NAME'),
        'bucket':os.environ.get('CONTENT_HUB_PACKAGES_BUCKET_NAME')}
    PreparedOrphanRuntime(dynamodb=None,s3=None,registry_guard=lambda:None,**config)
    import boto3
    ddb=boto3.client('dynamodb')
    def guard(): return _condition_check(load_active_service_binding(ddb,expected_descriptor=descriptor,trusted_resource_scope=scope))
    runtime=PreparedOrphanRuntime(dynamodb=ddb,s3=boto3.client('s3'),registry_guard=guard,**config)
    return collect_prepared_candidate(event['preparationId'],runtime=runtime)
