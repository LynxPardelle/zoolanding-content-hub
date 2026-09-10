"""Dedicated THN outbox consumer. No content writes or authoring invocation.

Requests use a durable, deterministic CloudFront caller reference; delivery is
complete only after CloudFront confirms it. A bounded partition cursor retries
interrupted pages instead of discarding their events. Schedules remain disabled.
"""
from copy import deepcopy
import hashlib
import json
import os
import re
import time

from service_binding_registry_consumer_v2 import marshal_item, unmarshal_item

METADATA_TABLE='zoolanding-content-hub-test-ThnContentHubV2Metadata'
FUNCTION_NAME='zoolanding-content-hub-test-ThnV2Invalidation'
OUTBOX_PREFIX='OUTBOX#test#thehairnarrative.com#thehairnarrative-com-journal#'
PUBLICATION_PK=OUTBOX_PREFIX+'PUBLICATION'
GLOBALS={'/','/the-journal','/sitemap.xml','/content-hub-search.json'}
SERIES='(?:form-and-movement|forma-y-movimiento|observation-and-process|observacion-y-proceso|bridal-forms|formas-nupciales)'
PATH_ID=r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}'


class InvalidationError(RuntimeError): pass
class HandlerNotActiveError(InvalidationError): pass


def _reject(): raise InvalidationError('invalidation_unavailable')


def _partition(pk):
    if pk==PUBLICATION_PK: return 'OPERATION#'
    if isinstance(pk,str) and re.fullmatch(re.escape(OUTBOX_PREFIX)+r'WITHDRAWAL#[0-9]{20}',pk) and int(pk.rsplit('#',1)[1])>0:
        return 'BATCH#'
    _reject()


def _key(pk,sk):
    prefix=_partition(pk)
    pattern=r'OPERATION#[a-f0-9]{32}' if prefix=='OPERATION#' else r'BATCH#[0-9]{20}'
    if not isinstance(sk,str) or not re.fullmatch(pattern,sk): _reject()
    return {'pk':pk,'sk':sk}


def _event(row,pk,sk):
    common={'pk','sk','recordType','schemaVersion','environment','domain','hubId','source','manifestId',
        'projectionDigest','writerEpoch','status','paths','pathCount','attemptCount'}
    fields={'operation','articleId','locale'} if pk==PUBLICATION_PK else {'batchNumber'}
    if not isinstance(row,dict) or set(row)-(common|fields|{'deliveryReceipt'}) or not common|fields <= set(row): _reject()
    if (any(row.get(k)!=v for k,v in {'pk':pk,'sk':sk,'recordType':'THN_CONTENT_HUB_V2_INVALIDATION_OUTBOX',
        'schemaVersion':1,'environment':'test','domain':'thehairnarrative.com','hubId':'thehairnarrative-com-journal'}.items())
        or type(row['schemaVersion']) is not int or row['status'] not in {'pending','submitted','delivered'}
        or type(row['writerEpoch']) is not int or row['writerEpoch']<1
        or type(row['attemptCount']) is not int or row['attemptCount']<0
        or not isinstance(row['manifestId'],str) or not re.fullmatch(r'[A-Za-z0-9._:-]{1,128}',row['manifestId'])
        or not isinstance(row['projectionDigest'],str) or not re.fullmatch(r'[a-f0-9]{64}',row['projectionDigest'])): _reject()
    if pk==PUBLICATION_PK:
        if row['source']!='publication' or row['operation'] not in {'publish','unpublish'} or row['locale'] not in {'en','es'} or not re.fullmatch(PATH_ID,str(row['articleId'])): _reject()
    elif row['source']!='emergency-withdraw' or row['writerEpoch']!=int(pk.rsplit('#',1)[1]) or type(row['batchNumber']) is not int or row['batchNumber']!=int(sk.split('#')[1]): _reject()
    paths=row['paths']
    if not isinstance(paths,list) or not 1<=len(paths)<=1000 or type(row['pathCount']) is not int or len(paths)!=row['pathCount']: _reject()
    for path in paths:
        if not isinstance(path,str) or len(path)>1024: _reject()
        if path not in GLOBALS and not re.fullmatch('/the-journal/'+SERIES+r'(?:/[a-z0-9]+(?:-[a-z0-9]+)*)?',path) and not re.fullmatch(
            '/features/content-hub-v2/public-media/'+PATH_ID+'/(?:en|es)/'+PATH_ID+'/'+PATH_ID+'/(?:w480|w768|w1200|w1600)',path): _reject()
    if len(paths)!=len(set(paths)): _reject()
    material={k:row[k] for k in sorted(common|fields) if k not in {'status','attemptCount'}}
    digest=hashlib.sha256(json.dumps(material,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    receipt=row.get('deliveryReceipt')
    if row['status']!='pending':
        if (not isinstance(receipt,dict) or set(receipt)!={'eventDigest','callerReference','invalidationId','completedAtEpoch'}
            or receipt['eventDigest']!=digest or receipt['callerReference']!='thn-v2-'+digest
            or not isinstance(receipt['invalidationId'],str) or not re.fullmatch(r'[A-Za-z0-9]{1,128}',receipt['invalidationId'])
            or type(receipt['completedAtEpoch']) is not int or receipt['completedAtEpoch']<0
            or (row['status']=='delivered')!=(receipt['completedAtEpoch']>0)): _reject()
    elif receipt is not None: _reject()
    return digest


class InvalidationRuntime:
    def __init__(self,*,dynamodb,cloudfront,table,distribution_id,clock=None):
        if table!=METADATA_TABLE or not isinstance(distribution_id,str) or not re.fullmatch(r'E[A-Z0-9]{4,31}',distribution_id): _reject()
        self.ddb,self.cache,self.table,self.distribution,self.clock=dynamodb,cloudfront,table,distribution_id,clock or time.time

    def read(self,key):
        result=self.ddb.get_item(TableName=self.table,Key=marshal_item(key),ConsistentRead=True)
        return unmarshal_item(result['Item']) if result.get('Item') else None


def deliver_invalidation_event(pk,sk,*,runtime):
    key=_key(pk,sk)
    try:
        row=runtime.read(key);digest=_event(row,pk,sk)
        if row['status']=='delivered': return {'status':'delivered'}
        reference='thn-v2-'+digest
        if row['status']=='submitted':
            value=runtime.cache.get_invalidation(DistributionId=runtime.distribution,Id=row['deliveryReceipt']['invalidationId'])['Invalidation']
            if value.get('Id')!=row['deliveryReceipt']['invalidationId']: _reject()
        else:
            value=runtime.cache.create_invalidation(DistributionId=runtime.distribution,InvalidationBatch={
                'CallerReference':reference,'Paths':{'Quantity':len(row['paths']),'Items':deepcopy(row['paths'])}})['Invalidation']
        if value.get('Status') not in {'InProgress','Completed'} or not re.fullmatch(r'[A-Za-z0-9]{1,128}',str(value.get('Id',''))): _reject()
        done=value['Status']=='Completed';status='delivered' if done else 'submitted'
        receipt={'eventDigest':digest,'callerReference':reference,'invalidationId':value['Id'],
            'completedAtEpoch':int(runtime.clock()) if done else 0}
        runtime.ddb.update_item(TableName=runtime.table,Key=marshal_item(key),
            UpdateExpression='SET #status = :next, deliveryReceipt = :receipt',
            ConditionExpression='#status = :before AND paths = :paths AND projectionDigest = :digest AND writerEpoch = :epoch',
            ExpressionAttributeNames={'#status':'status'},ExpressionAttributeValues=marshal_item({
                ':next':status,':receipt':receipt,':before':row['status'],':paths':row['paths'],
                ':digest':row['projectionDigest'],':epoch':row['writerEpoch']}))
        return {'status':status}
    except InvalidationError: raise
    except Exception: raise InvalidationError('invalidation_retry_required') from None


def process_partition(pk,*,runtime):
    prefix=_partition(pk);cursor_key={'pk':pk,'sk':'WORKER#CURSOR'}
    cursor=runtime.read(cursor_key)
    start=cursor.get('cursor','') if cursor else ''
    args={'TableName':runtime.table,'ConsistentRead':True,'Limit':25,
        'KeyConditionExpression':'pk = :pk AND begins_with(sk, :prefix)',
        'ExpressionAttributeValues':marshal_item({':pk':pk,':prefix':prefix})}
    if start: args['ExclusiveStartKey']=marshal_item(_key(pk,start))
    response=runtime.ddb.query(**args);count=0;pending=False
    for item in response.get('Items',[]):
        row=unmarshal_item(item)
        if row.get('pk')!=pk: _reject()
        result=deliver_invalidation_event(pk,row.get('sk'),runtime=runtime)
        pending=pending or result['status']!='delivered';count+=1
    # An incomplete page stays current; a fresh pass polls submitted receipts.
    last=unmarshal_item(response.get('LastEvaluatedKey',{}))
    following=last.get('sk','')
    if last and (last.get('pk')!=pk or _key(pk,following)!=last): _reject()
    if not pending:
        runtime.ddb.update_item(TableName=runtime.table,Key=marshal_item(cursor_key),
            UpdateExpression='SET #cursor = :next',ConditionExpression='attribute_not_exists(#cursor) OR #cursor = :before',
            ExpressionAttributeNames={'#cursor':'cursor'},ExpressionAttributeValues=marshal_item({':next':following,':before':start}))
    return {'processed':count,'pending':pending,'hasMore':bool(following)}


def lambda_handler(event,context):
    if event=={'schemaVersion':1,'source':'thn-invalidation-schedule'}: pk=PUBLICATION_PK
    elif isinstance(event,dict) and set(event)=={'schemaVersion','source','writerEpoch'} and event['schemaVersion']==1 and event['source']=='thn-invalidation-withdrawal' and type(event['writerEpoch']) is int and 0<event['writerEpoch']<10**20:
        pk=OUTBOX_PREFIX+f"WITHDRAWAL#{event['writerEpoch']:020d}"
    else: raise HandlerNotActiveError('invalidation_not_active')
    arn=getattr(context,'invoked_function_arn','')
    if not isinstance(arn,str) or not re.fullmatch(r'arn:aws:lambda:[a-z0-9-]+:[0-9]{12}:function:'+FUNCTION_NAME+':test',arn):
        raise HandlerNotActiveError('invalidation_not_active')
    table=os.environ.get('THN_CONTENT_HUB_METADATA_TABLE_NAME');distribution=os.environ.get('THN_CONTENT_HUB_PUBLIC_DISTRIBUTION_ID')
    # Validate configuration before constructing SDK clients.
    InvalidationRuntime(dynamodb=None,cloudfront=None,table=table,distribution_id=distribution)
    import boto3
    runtime=InvalidationRuntime(dynamodb=boto3.client('dynamodb'),cloudfront=boto3.client('cloudfront'),table=table,distribution_id=distribution)
    return process_partition(pk,runtime=runtime)
