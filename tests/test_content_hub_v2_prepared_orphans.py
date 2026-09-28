import unittest
from copy import deepcopy
from unittest.mock import patch
from botocore.exceptions import ClientError
from tests import test_content_hub_v2_finalization as fixtures
from content_hub_v2_preparation import _bytes, _sha
from content_hub_v2_projection_store import PARTITION, METADATA_TABLE
from content_hub_v2_registry_fence import marshal_item, _condition_check
from content_hub_v2_state_keys import ARTICLE_PK
import prepared_orphan_collector_lambda as collector


class PreparedOrphansTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.FinalizationTests();self.f.setUp();self.f.prepare()
        self.id='prep-'+_sha(_bytes(['a1','en','r1']))
        self.now=self.f.now+31*86400;self.deletes=[]
        self.f.prepare(revision='r2')
        original_get=self.f.s3.get_object
        def get(**kw):
            try: return original_get(**kw)
            except KeyError: raise ClientError({'Error':{'Code':'NoSuchKey'}},'GetObject') from None
        def delete(**kw):
            self.assertEqual(set(kw),{'Bucket','Key','VersionId'})
            obj=self.f.s3.objects.get((kw['Bucket'],kw['Key']))
            if obj: self.assertEqual(obj['VersionId'],kw['VersionId'])
            self.deletes.append(kw);self.f.s3.objects.pop((kw['Bucket'],kw['Key']),None)
        self.f.s3.get_object=get;self.f.s3.delete_object=delete
        self.runtime=collector.PreparedOrphanRuntime(dynamodb=self.f.ddb,s3=self.f.s3,
            table=METADATA_TABLE,public_table=self.f.public_table,bucket=self.f.delivery_bucket,
            registry_guard=lambda:_condition_check(self.f.registry),clock=lambda:self.now)

    def row(self): return self.f.ddb.row(METADATA_TABLE,{'pk':PARTITION,'sk':'PREPARATION#'+self.id})
    def collect(self): return collector.collect_prepared_candidate(self.id,runtime=self.runtime)

    def test_claim_wait_and_delete_only_exact_old_versions_then_replay(self):
        self.assertEqual(self.collect()['state'],'collecting');self.assertFalse(self.deletes)
        self.now+=collector.QUIET_PERIOD_SECONDS
        self.assertEqual(self.collect()['state'],'collected');self.assertEqual(len(self.deletes),5)
        self.assertEqual(self.collect()['state'],'collected');self.assertEqual(len(self.deletes),5)
        self.assertTrue(all('/r1/' in d['Key'] for d in self.deletes))
        self.assertTrue(any('/r2/' in key for _,key in self.f.s3.objects))

    def test_young_and_current_working_revisions_are_kept(self):
        self.now=self.f.now+86400
        self.assertEqual(self.collect()['state'],'retained')
        self.now+=40*86400
        self.id='prep-'+_sha(_bytes(['a1','en','r2']))
        self.assertEqual(self.collect()['state'],'retained');self.assertFalse(self.deletes)

    def test_live_revision_is_never_collected(self):
        self.f.publish(revision='r2')
        self.id='prep-'+_sha(_bytes(['a1','en','r2']))
        self.assertEqual(self.collect()['state'],'retained');self.assertFalse(self.deletes)

    def test_digest_change_aborts_all_deletes(self):
        self.collect();self.now+=collector.QUIET_PERIOD_SECONDS
        receipt=next(iter(self.row()['receipts'].values()))
        self.f.s3.objects[self.f.delivery_bucket,receipt['key']]['body']=b'changed'
        with self.assertRaises(collector.CollectionError): self.collect()
        self.assertFalse(self.deletes)

    def test_reference_race_fails_the_claim_atomically(self):
        def race(ddb):
            row=deepcopy(self.f.article());row['locales']['en']['workingRevisionId']='r1';ddb.seed(METADATA_TABLE,row)
        self.f.ddb.before_commit=race
        with self.assertRaises(collector.CollectionError): self.collect()
        self.assertEqual(self.row()['state'],'preparing');self.assertFalse(self.deletes)

    def test_cross_scope_candidate_and_malformed_invocation_deny_before_io(self):
        for candidate in ['../other','prep-'+'x'*64,'other-article']:
            with self.assertRaises(collector.CollectionError): collector.collect_prepared_candidate(candidate,runtime=self.runtime)
        with patch('boto3.client') as client, self.assertRaises(collector.HandlerNotActiveError): collector.lambda_handler({'unexpected':'input'},object())
        client.assert_not_called()


if __name__=='__main__': unittest.main()
