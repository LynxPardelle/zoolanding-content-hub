from copy import deepcopy
import unittest
from unittest.mock import Mock
import content_hub_v2_private_asset_gc as gc
from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE as SCOPE

NOW=2_000_000
class Store:
    def __init__(self):
        self.asset={**SCOPE,"articleId":"a1","locale":"en","assetId":"m1","recordPurpose":"client-owner",
                    "status":"ready","deliveryState":"private","referenceCount":0,"createdAtEpoch":1,
                    "variants":[{"variantId":v,"contentType":"image/webp","sha256":"a"*64,"versionId":"v1",
                                 "key":f"private/test/thehairnarrative.com/journal-owner/thehairnarrative-com/thehairnarrative-com-journal/articles/a1/en/revisions/r1/assets/m1/{v}.webp"}
                                for v in ["w480","w768","w1200","w1600"]]}
        self.article={**SCOPE,"articleId":"a1","recordPurpose":"client-owner","concurrencyToken":"v1",
                      "locales":{"en":{"workingAssetIds":[],"publishedAssetIds":[]}}}
        self.deleted=[];self.claimed=False;self.race=False
    def read_asset(self,c):return deepcopy(self.asset)
    def read_article(self,c):return deepcopy(self.article)
    def claim(self,asset,article):
        if self.race:raise RuntimeError("changed")
        self.claimed=True;self.asset["status"]="collecting"
    def delete_variant(self,v):self.deleted.append((v["key"],v["versionId"]))
    def finish(self,asset):self.asset["status"]="collected"

class PrivateGcTests(unittest.TestCase):
    def setUp(self):
        self.store=Store()
        self.candidate={"articleId":"a1","locale":"en","assetId":"m1"}
    def collect(self):
        return gc.collect_private_assets([self.candidate],store=self.store,now_epoch=NOW)
    def test_exact_unreferenced_old_private_asset_is_collected_once(self):
        self.assertEqual(self.collect(),{"collected":1,"skipped":0,"failed":0})
        self.assertEqual(len(self.store.deleted),4)
        self.assertEqual(self.collect()["skipped"],1)
        self.assertEqual(len(self.store.deleted),4)
    def test_referenced_live_young_wrong_scope_or_untracked_records_are_never_deleted(self):
        cases=[("asset","referenceCount",1),("asset","deliveryState","live"),
               ("asset","referencesUpdatedAtEpoch",NOW-1),("asset","createdAtEpoch",NOW-1),
               ("asset","domain","another.test"),("asset","status","processing")]
        for which,key,value in cases:
            with self.subTest(key=key):
                self.store=Store();getattr(self.store,which)[key]=value
                self.collect();self.assertEqual(self.store.deleted,[])
        for field in ["workingAssetIds","publishedAssetIds"]:
            self.store=Store();self.store.article["locales"]["en"][field]=["m1"]
            self.collect();self.assertEqual(self.store.deleted,[])
        self.store=Store();del self.store.article["locales"]["en"]["workingAssetIds"]
        self.collect();self.assertEqual(self.store.deleted,[])
    def test_claim_race_and_cross_prefix_or_missing_version_fail_before_delete(self):
        self.store.race=True
        self.assertEqual(self.collect()["failed"],1);self.assertEqual(self.store.deleted,[])
        for key,value in [("key","private/other/asset.webp"),("versionId","null")]:
            self.store=Store();self.store.asset["variants"][0][key]=value
            self.collect();self.assertEqual(self.store.deleted,[])
    def test_bounded_closed_input(self):
        with self.assertRaises(ValueError):
            gc.collect_private_assets([self.candidate]*21,store=self.store,now_epoch=NOW)
        self.candidate["bucket"]="forbidden"
        with self.assertRaises(ValueError):self.collect()
        self.assertEqual(self.store.deleted,[])
    def test_partial_delete_resumes_from_claimed_state(self):
        actual=self.store.delete_variant
        self.store.delete_variant=Mock(side_effect=RuntimeError("unavailable"))
        self.assertEqual(self.collect()["failed"],1)
        self.assertTrue(self.store.claimed)
        self.store.delete_variant=actual
        self.assertEqual(self.collect()["collected"],1)

    def test_real_adapter_claim_fences_article_asset_and_registry_before_versioned_delete(self):
        from tests.test_service_binding_registry_v2 import build_record, registry_definition
        binding=build_record(registry_definition(activationStatus="active",writerMode="client-owner",writerEpoch=7))
        ddb,s3=Mock(),Mock()
        store=gc.AwsPrivateAssetCollector(ddb,s3,bucket="zlp-thn-private-upload-test-123456789012-us-east-1",
            expected_descriptor={},trusted_scope={"accountId":"123456789012","region":"us-east-1"},writer_epoch=7)
        store._binding=Mock(return_value=binding)
        store.claim(self.store.asset,self.store.article)
        tx=ddb.transact_write_items.call_args.kwargs["TransactItems"]
        self.assertEqual(len(tx),3)
        self.assertIn("#writerEpoch",tx[0]["ConditionCheck"]["ConditionExpression"])
        self.assertIn("concurrencyToken",tx[1]["ConditionCheck"]["ConditionExpression"])
        self.assertIn("variants",tx[2]["Update"]["ExpressionAttributeNames"].values())
        s3.delete_object.assert_not_called()
        store.delete_variant(self.store.asset["variants"][0])
        self.assertEqual(s3.delete_object.call_args.kwargs["VersionId"],"v1")
        self.assertFalse(s3.list_objects_v2.called)

    def test_gc_role_can_only_delete_exact_versions_and_schedule_stays_disabled(self):
        from test_thn_content_hub_v2_task_019_template import _resource, _template
        role=_resource(_template(),"ThnContentHubV2PrivateAssetCollectorRole")
        self.assertIn("s3:DeleteObjectVersion",role)
        self.assertIn("journal-owner/thehairnarrative-com/thehairnarrative-com-journal/articles/*",role)
        self.assertNotIn("dynamodb:Query",role)
        self.assertNotIn("dynamodb:DeleteItem",role)
        self.assertIn("zlp-thn-private-upload-test-",role)
        function=_resource(_template(),"ThnContentHubV2PrivateAssetCollectorFunction")
        self.assertIn("Enabled: false",function)
        self.assertIn("THN_CONTENT_HUB_DESCRIPTOR_SHA256",function)
        self.assertIn("THN_CONTENT_HUB_PRIVATE_MEDIA_BUCKET_NAME",function)

if __name__=="__main__":unittest.main()
