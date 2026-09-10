import io
import unittest
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch

from botocore.session import Session
from botocore.validate import validate_parameters
from botocore.exceptions import ClientError
from content_hub_v2_registry_fence import marshal_item, unmarshal_item
import invalidation_worker_lambda as worker


class OutboxDynamo:
    def __init__(self, row):
        self.rows={(row['pk'], row['sk']):deepcopy(row)}; self.calls=[]; self.fail_update=False

    def get_item(self, **kw):
        self.calls.append(('get',kw)); assert kw['ConsistentRead']
        key=unmarshal_item(kw['Key']); row=self.rows.get((key['pk'],key['sk']))
        return {'Item':marshal_item(row)} if row else {}

    def query(self, **kw):
        validate_parameters(kw,Session().get_service_model('dynamodb').operation_model('Query').input_shape)
        self.calls.append(('query',kw)); values=unmarshal_item(kw['ExpressionAttributeValues'])
        rows=[r for (pk,sk),r in sorted(self.rows.items()) if pk==values[':pk'] and sk.startswith(values[':prefix'])]
        return {'Items':[marshal_item(r) for r in rows[:kw['Limit']]]}

    def update_item(self, **kw):
        validate_parameters(kw,Session().get_service_model('dynamodb').operation_model('UpdateItem').input_shape)
        self.calls.append(('update',kw))
        if self.fail_update: self.fail_update=False; raise RuntimeError('simulated write interruption')
        key=unmarshal_item(kw['Key']); identity=(key['pk'],key['sk']); row=self.rows.get(identity)
        values=unmarshal_item(kw['ExpressionAttributeValues'])
        if key['sk']=='WORKER#CURSOR':
            self.rows[identity]={**key,'cursor':values[':next']}; return {}
        if row['status'] not in ('pending','submitted'): raise ClientError({'Error':{'Code':'ConditionalCheckFailedException'}},'UpdateItem')
        if row['paths']!=values[':paths']: raise AssertionError('event was changed')
        row.update(status=values[':next'],deliveryReceipt=values[':receipt'])
        return {}


class Cache:
    def __init__(self): self.created=[];self.polls=[];self.complete=True
    def create_invalidation(self,**kw):
        validate_parameters(kw,Session().get_service_model('cloudfront').operation_model('CreateInvalidation').input_shape)
        self.created.append(deepcopy(kw))
        return {'Invalidation':{'Id':'I123','Status':'Completed' if self.complete else 'InProgress'}}
    def get_invalidation(self,**kw):
        self.polls.append(kw);return {'Invalidation':{'Id':'I123','Status':'Completed' if self.complete else 'InProgress'}}


class InvalidationTests(unittest.TestCase):
    def setUp(self):
        self.row={'pk':worker.PUBLICATION_PK,'sk':'OPERATION#'+'a'*32,
            'recordType':'THN_CONTENT_HUB_V2_INVALIDATION_OUTBOX','schemaVersion':1,
            'environment':'test','domain':'thehairnarrative.com','hubId':'thehairnarrative-com-journal',
            'source':'publication','operation':'publish','articleId':'article1','locale':'en',
            'manifestId':'manifest1','projectionDigest':'b'*64,'writerEpoch':2,
            'status':'pending','paths':['/','/the-journal','/the-journal/bridal-forms/first-letter',
                '/sitemap.xml','/content-hub-search.json',
                '/features/content-hub-v2/public-media/article1/en/rev1/cover/w480'],
            'pathCount':6,'attemptCount':0}
        self.ddb=OutboxDynamo(self.row);self.cache=Cache()
        self.runtime=worker.InvalidationRuntime(dynamodb=self.ddb,cloudfront=self.cache,
            table=worker.METADATA_TABLE,distribution_id='E123456',clock=lambda:1000)

    def deliver(self): return worker.deliver_invalidation_event(self.row['pk'],self.row['sk'],runtime=self.runtime)

    def test_exact_keys_complete_and_replay_without_second_request(self):
        self.assertEqual(self.deliver()['status'],'delivered')
        self.assertEqual(self.deliver()['status'],'delivered')
        self.assertEqual(len(self.cache.created),1)
        self.assertEqual(self.cache.created[0]['InvalidationBatch']['Paths']['Items'],self.row['paths'])
        self.assertEqual({c[0] for c in self.ddb.calls},{'get','update'})

    def test_interrupted_receipt_uses_identical_cache_idempotency_key(self):
        self.ddb.fail_update=True
        with self.assertRaises(worker.InvalidationError): self.deliver()
        self.deliver()
        self.assertEqual(self.cache.created[0],self.cache.created[1])

    def test_in_progress_is_not_reported_delivered_until_confirmed(self):
        self.cache.complete=False
        self.assertEqual(self.deliver()['status'],'submitted')
        self.cache.complete=True
        self.assertEqual(self.deliver()['status'],'delivered')
        self.assertEqual(len(self.cache.created),1);self.assertEqual(len(self.cache.polls),1)

    def test_unsafe_foreign_or_tampered_paths_never_reach_cache(self):
        for path in ['/admin/journal','/*','https://example.invalid/','/the-journal/../admin','/the-journal?draftDomain=other.com','/blog/other','/features/content-hub-v2/public-media/a/fr/b/c/w480']:
            with self.subTest(path=path):
                self.ddb.rows[(self.row['pk'],self.row['sk'])]={**self.row,'paths':[path],'pathCount':1}
                with self.assertRaises(worker.InvalidationError): self.deliver()
        self.assertFalse(self.cache.created)
        with self.assertRaises(worker.InvalidationError): worker.deliver_invalidation_event('OUTBOX#other','OPERATION#'+'a'*32,runtime=self.runtime)

    def test_withdrawal_partition_and_batch_are_closed(self):
        row={k:v for k,v in self.row.items() if k not in {'operation','articleId','locale'}}
        row.update(pk=worker.OUTBOX_PREFIX+'WITHDRAWAL#00000000000000000003',sk='BATCH#00000000000000000001',
            source='emergency-withdraw',writerEpoch=3,batchNumber=1)
        self.ddb.rows[(row['pk'],row['sk'])]=row
        self.assertEqual(worker.deliver_invalidation_event(row['pk'],row['sk'],runtime=self.runtime)['status'],'delivered')

    def test_schedule_is_bounded_and_keeps_a_retryable_cursor(self):
        result=worker.process_partition(worker.PUBLICATION_PK,runtime=self.runtime)
        self.assertEqual(result['processed'],1)
        query=next(value for kind,value in self.ddb.calls if kind=='query')
        self.assertEqual(query['Limit'],25);self.assertTrue(query['ConsistentRead'])
        self.assertNotIn('FilterExpression',query)

    def test_bad_event_and_context_fail_before_any_clients(self):
        with patch('boto3.client') as client, self.assertRaises(worker.HandlerNotActiveError):
            worker.lambda_handler({'unexpected':'input'},object())
        client.assert_not_called()


if __name__=='__main__': unittest.main()
