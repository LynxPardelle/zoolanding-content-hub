"""Real THN finalization against local conditional storage, never AWS."""
from copy import deepcopy
from datetime import datetime,timezone
import importlib.util
import json
import os
import unittest

from atomic_publication_fixture import AtomicDynamo
from test_content_hub_v2_preparation_store import ExactS3
from test_content_hub_v2_preparation import MemoryPreparationStore
from test_content_hub_v2_authorization import FakeAuthorizationStore,REGISTRY,current_user,session
from tests.test_service_binding_registry_v2 import build_record,registry_definition
from content_hub_v2_authorization import load_authorization_context,THN_CURRENT_USER_SCOPE
from content_hub_v2_actor_fence import actor_condition_checks,USER_TABLE,SESSION_TABLE
from content_hub_v2_registry_fence import _condition_check
from content_hub_v2_editor_store import METADATA_TABLE,AUDIT_TABLE,ARTICLE_PK,PARTITION_PREFIX,PRIVATE_PREFIX
from content_hub_v2_preparation import prepare_immutable_objects,_bytes,_sha,SOURCE_ROOT
from content_hub_v2_projection_store import PARTITION as PREPARATION_PK
from content_hub_v2_projection import VARIANTS
from content_hub_v2_projection_manifest import MANIFEST_PK,MANIFEST_SK,validate_projection_manifest,validate_projection_page


class FinalizationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("content_hub_v2_finalization"),"the final atomic publication store is not implemented")
        self.module=__import__("content_hub_v2_finalization")
        self.ddb=AtomicDynamo();self.s3=ExactS3();self.now=1788888000
        self.registry=build_record(registry_definition(activationStatus="active",writerMode="client-owner",writerEpoch=7,registryRevision=3))
        self.auth=load_authorization_context(FakeAuthorizationStore(),session_id_hash="a"*64,registry_record=REGISTRY,now_epoch=1000)
        self.ddb.seed(_condition_check(self.registry)["ConditionCheck"]["TableName"],self.registry)
        self.ddb.seed(USER_TABLE,current_user())
        self.ddb.seed(SESSION_TABLE,session(idleExpiresAt=self.now+1500,absoluteExpiresAt=self.now+2000,expiresAt=self.now+2000))
        self.public_table="fixture-public-table"
        self.private_bucket="zlp-thn-ch-test-private-000000000000-us-east-1"
        self.delivery_bucket="fixture-thn-public-packages"
        self.store=self.module.AwsPublicationStore(dynamodb=self.ddb,s3=self.s3,
            account_id="000000000000",region="us-east-1",source_bucket="zlp-thn-private-upload-test-000000000000-us-east-1",
            delivery_bucket=self.delivery_bucket,private_bucket=self.private_bucket,public_table=self.public_table,
            guard_factory=lambda:[_condition_check(self.registry),*actor_condition_checks(self.auth,"a"*64,self.now)])
        self.ddb.seed(self.public_table,{"pk":"HUB#zoosite-main","sk":"ARTICLE#untouched","title":"Unrelated synthetic record"})

    def article(self,article="a1"):
        return self.ddb.row(METADATA_TABLE,{"pk":ARTICLE_PK,"sk":"ARTICLE#"+article})

    def prepare(self,article="a1",locale="en",revision="r1",asset="m1",title="Quiet shape",allocate=False,inline=()):
        now=datetime.fromtimestamp(self.now,timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
        row=deepcopy(self.article(article)) if self.article(article) else {**THN_CURRENT_USER_SCOPE,
            "pk":ARTICLE_PK,"sk":"ARTICLE#"+article,"articleId":article,"recordPurpose":"client-owner",
            "seriesId":"bridal-forms","seriesLocked":False,"createdAt":now,"updatedAt":now,"locales":{}}
        state=row["locales"].get(locale,{})
        before_working=state.get("workingAssetIds",[]);before_published=state.get("publishedAssetIds",[])
        row["concurrencyToken"]="edit-"+revision
        package={"title":title,"summary":"A small observation.","seriesId":"bridal-forms","tags":["private"],
            "cover":{"assetId":asset,"alt":"Hair","focalX":50,"focalY":50},"delta":{"ops":[{"insert":"A small observation.\n"}]}}
        package["delta"]["ops"].extend({"insert":{"image":image}} for image in inline)
        working_ids={asset,*inline}
        key=PRIVATE_PREFIX+f"immutable-revisions/{article}/{locale}/{revision}/package.json"
        body=_bytes(package)
        self.s3.objects[self.private_bucket,key]={"VersionId":"private-v1","ContentType":"application/json","body":body}
        row["locales"][locale]={**state,"title":title,"summary":package["summary"],"tags":package["tags"],
            "workingRevisionId":revision,"workingAssetIds":sorted(working_ids),"publishedAssetIds":before_published,
            "packagePointer":{"key":key,"versionId":"private-v1","sha256":_sha(body)}}
        self.ddb.seed(METADATA_TABLE,row)
        memory=MemoryPreparationStore();assets={}
        for asset_id in set(before_working)|set(before_published)|working_ids:
            asset_key={"pk":PARTITION_PREFIX+f"ASSETS#{article}#{locale}","sk":"ASSET#"+asset_id}
            asset_row=deepcopy(self.ddb.row(METADATA_TABLE,asset_key))
            if asset_row is None:
                variants=[]
                for variant_id in VARIANTS:
                    data=("synthetic-image-"+asset_id+variant_id).encode()
                    variant={"variantId":variant_id,"key":SOURCE_ROOT+f"{article}/{locale}/revisions/upload-1/assets/{asset_id}/{variant_id}.webp",
                             "versionId":"source-v1","contentType":"image/webp","bytes":len(data),"sha256":_sha(data),"width":100,"height":100}
                    variants.append(variant)
                asset_row={**asset_key,**THN_CURRENT_USER_SCOPE,"recordPurpose":"client-owner","articleId":article,
                           "locale":locale,"assetId":asset_id,"status":"ready","deliveryState":"private","alt":"Hair","variants":variants}
            asset_row["referenceCount"]=int(asset_id in working_ids)+int(asset_id in before_published)
            self.ddb.seed(METADATA_TABLE,asset_row)
            assets[asset_id]=asset_row
            for variant in asset_row["variants"]:
                memory.sources[variant["key"],variant["versionId"]]=("synthetic-image-"+asset_id+variant["variantId"]).encode()
        from content_hub_v2_editor_model import article_path
        path=state.get("path") or article_path(locale,row["seriesId"],title)
        allocation=None
        if allocate:
            self.assertTrue(callable(getattr(self.store,"allocate_publication",None)),"reserve automatic URLs before writing immutable bundles")
            allocation=self.store.allocate_publication(article_id=article,locale=locale,revision_id=revision,
                expected_token=row["concurrencyToken"])
            path=allocation["path"]
        # An unchanged retired revision reuses its existing immutable package.
        prep_id="prep-"+_sha(_bytes([article,locale,revision]))
        if not self.ddb.row(METADATA_TABLE,{"pk":PREPARATION_PK,"sk":"PREPARATION#"+prep_id}):
            result=prepare_immutable_objects(article_id=article,locale=locale,revision_id=revision,package=package,
                assets=assets,path=path,first_published_at=(allocation or {}).get("firstPublishedAt") or state.get("firstPublishedAt") or now,
                updated_at=(allocation or {}).get("updatedAt") or now,
                purpose="client-owner",now_epoch=self.now,store=memory,authorize=lambda:None)
            self.ddb.seed(METADATA_TABLE,{"pk":PREPARATION_PK,"sk":"PREPARATION#"+prep_id,
                "intent":memory.intents[prep_id],"state":"preparing","receipts":{
                    _sha(r["key"].encode()):r for r in result["objects"]}})
            for object_key,entry in memory.objects.items():
                self.s3.objects[self.delivery_bucket,object_key]={"VersionId":entry["receipt"]["versionId"],
                    "ContentType":entry["receipt"]["contentType"],"body":entry["body"]}
        return row["concurrencyToken"]

    def publish(self,article="a1",locale="en",revision="r1",operation="1"*32,token=None):
        return self.store.finalize_publication_transaction(article_id=article,locale=locale,revision_id=revision,
            expected_token=token or self.article(article)["concurrencyToken"],operation_id=operation)

    def unpublish(self,article="a1",locale="en",operation="2"*32,token=None):
        return self.store.finalize_unpublish_transaction(article_id=article,locale=locale,
            expected_token=token or self.article(article)["concurrencyToken"],operation_id=operation)

    def public_rows(self):
        return {key:deepcopy(value) for key,value in self.ddb.items.items() if key[0]==self.public_table}

    def test_publication_commits_private_public_references_manifest_and_outbox_once(self):
        self.prepare();result=self.publish()
        self.assertEqual(result["state"],"published")
        self.assertEqual(self.article()["locales"]["en"]["publishedRevisionId"],"r1")
        self.assertEqual(self.article()["locales"]["en"]["publishedAssetIds"],["m1"])
        asset=self.ddb.row(METADATA_TABLE,{"pk":PARTITION_PREFIX+"ASSETS#a1#en","sk":"ASSET#m1"})
        self.assertEqual(asset["referenceCount"],2)
        self.assertEqual(len(self.public_rows()),5)
        manifest=validate_projection_manifest(self.ddb.row(METADATA_TABLE,{"pk":MANIFEST_PK,"sk":MANIFEST_SK}))
        self.assertEqual(manifest["livePointerCount"],4)
        self.assertEqual(manifest["headPageId"],"a1")
        page=validate_projection_page(self.ddb.row(METADATA_TABLE,{"pk":MANIFEST_PK,"sk":"PAGE#a1"}))
        self.assertEqual(page["pointerCount"],4)
        events=[r for (table,_),r in self.ddb.items.items() if table==METADATA_TABLE and r.get("source")=="publication"]
        self.assertEqual(len(events),1)
        self.assertIn("/",events[0]["paths"])
        transactions=[kw for op,kw in self.ddb.calls if op=="transaction"]
        self.assertEqual(len(transactions),1)
        self.assertEqual(len([x for x in transactions[0]["TransactItems"] if "ConditionCheck" in x and "SessionV2" in x["ConditionCheck"]["TableName"]]),1)

    def test_stale_session_cancels_all_public_private_and_outbox_changes(self):
        self.prepare();before=deepcopy(self.ddb.items)
        self.ddb.before_commit=lambda d:d.row(SESSION_TABLE,{"sessionIdHash":"a"*64}).update(revokedAt=self.now)
        with self.assertRaises(Exception): self.publish()
        self.assertEqual(self.public_rows(),{k:v for k,v in before.items() if k[0]==self.public_table})
        self.assertEqual(self.article(),before[self.ddb.identity(METADATA_TABLE,{"pk":ARTICLE_PK,"sk":"ARTICLE#a1"})])
        self.assertFalse(any(r.get("source")=="publication" for r in self.ddb.items.values()))

    def test_bilingual_update_unpublish_and_republish_keep_dates_paths_and_sibling(self):
        self.prepare(locale="es");self.publish(locale="es")
        first=deepcopy(self.article()["locales"]["es"])
        self.now+=10;self.prepare(locale="en",revision="r2");self.publish(revision="r2",operation="3"*32)
        key={"pk":"HUB#thehairnarrative-com-journal","sk":"ARTICLE#a1"}
        self.assertEqual(self.ddb.row(self.public_table,key)["locale"],"en")
        self.now+=10;self.prepare(locale="es",revision="r3",asset="m2",title="New title")
        self.publish(locale="es",revision="r3",operation="4"*32)
        state=self.article()["locales"]["es"]
        self.assertEqual(state["firstPublishedAt"],first["firstPublishedAt"])
        self.assertEqual(state["path"],first["path"])
        self.assertEqual(state["publishedAssetIds"],["m2"])
        self.assertEqual(self.ddb.row(METADATA_TABLE,{"pk":PARTITION_PREFIX+"ASSETS#a1#es","sk":"ASSET#m1"})["referenceCount"],0)
        self.unpublish(operation="5"*32)
        self.assertEqual(self.ddb.row(self.public_table,key)["locale"],"es")
        self.unpublish(locale="es",operation="6"*32)
        self.assertIsNone(self.ddb.row(self.public_table,key))
        self.assertEqual(self.article()["locales"]["es"]["workingRevisionId"],"r3")
        self.now+=50;self.publish(locale="es",revision="r3",operation="7"*32)
        self.assertEqual(self.ddb.row(self.public_table,key)["path"],first["path"])
        self.assertEqual(self.ddb.row(self.public_table,key)["publishedAt"],first["firstPublishedAt"])

    def test_exact_replay_is_freshly_fenced_without_duplicate_outbox(self):
        token=self.prepare();first=self.publish(token=token)
        before=deepcopy(self.ddb.items)
        self.assertEqual(self.publish(token=token),first)
        self.assertEqual(self.ddb.items,before)
        self.ddb.row(SESSION_TABLE,{"sessionIdHash":"a"*64})["revokedAt"]=self.now
        with self.assertRaises(Exception): self.publish(token=token)

    def test_other_article_pages_survive_removing_middle_head_and_tail(self):
        for n in range(1,4):
            self.prepare(article=f"a{n}",title=f"Shape {n}")
            self.publish(article=f"a{n}",operation=str(n)*32)
        for n in (2,3,1):
            self.unpublish(article=f"a{n}",operation=str(n+4)*32)
            header=validate_projection_manifest(self.ddb.row(METADATA_TABLE,{"pk":MANIFEST_PK,"sk":MANIFEST_SK}))
            page_id=header["headPageId"];seen=[];pointers=0
            while page_id:
                self.assertNotIn(page_id,seen);seen.append(page_id)
                page=validate_projection_page(self.ddb.row(METADATA_TABLE,{"pk":MANIFEST_PK,"sk":"PAGE#"+page_id}))
                pointers+=page["pointerCount"];page_id=page["nextPageId"]
            self.assertEqual(len(seen),header["remainingPageCount"])
            self.assertEqual(pointers,header["livePointerCount"])
        self.assertEqual(len(self.public_rows()),1)

    def test_changed_epoch_article_or_asset_at_commit_cancels_every_projection_change(self):
        self.prepare()
        for mutate in (
            lambda d:d.row(_condition_check(self.registry)["ConditionCheck"]["TableName"],{"pk":self.registry["pk"],"sk":self.registry["sk"]}).update(writerEpoch=8),
            lambda d:d.row(METADATA_TABLE,{"pk":ARTICLE_PK,"sk":"ARTICLE#a1"}).update(concurrencyToken="concurrent-edit"),
            lambda d:d.row(METADATA_TABLE,{"pk":PARTITION_PREFIX+"ASSETS#a1#en","sk":"ASSET#m1"}).update(status="collecting"),
        ):
            original=deepcopy(self.ddb.items);before=self.public_rows()
            self.ddb.before_commit=mutate
            with self.assertRaises(Exception): self.publish()
            self.assertEqual(self.public_rows(),before)
            self.assertFalse(any(r.get("source")=="publication" for r in self.ddb.items.values()))
            self.ddb.items=original

    def test_incomplete_or_collected_preparation_cannot_become_live(self):
        self.prepare()
        prep=next(r for r in self.ddb.items.values() if r.get("pk")==PREPARATION_PK)
        for mutate in (lambda r:r.update(state="collecting"),lambda r:r["receipts"].pop(next(iter(r["receipts"])))):
            original=deepcopy(self.ddb.items);mutate(prep)
            with self.assertRaises(Exception): self.publish()
            self.assertEqual(len(self.public_rows()),1)
            self.ddb.items=original;prep=next(r for r in self.ddb.items.values() if r.get("pk")==PREPARATION_PK)

    def test_another_article_cannot_claim_a_previously_published_path(self):
        self.prepare();self.publish();self.unpublish()
        self.prepare(article="a2")
        before=deepcopy(self.ddb.items)
        with self.assertRaises(Exception): self.publish(article="a2",operation="8"*32)
        self.assertEqual(self.ddb.items,before)

    def test_wrong_purpose_or_working_revision_cannot_publish(self):
        self.prepare();before=deepcopy(self.ddb.items)
        self.article()["recordPurpose"]="qa"
        with self.assertRaises(Exception): self.publish()
        self.assertEqual(len(self.public_rows()),1)
        self.ddb.items=before
        with self.assertRaises(Exception): self.publish(revision="not-current")
        self.assertEqual(self.ddb.items,before)

    def test_unchanged_locale_pointer_is_fenced_when_publishing_a_sibling(self):
        from content_hub_v2_editor_service import EditorConflict
        self.prepare(locale="es");self.publish(locale="es")
        self.prepare(locale="en",revision="r2")
        path=self.article()["locales"]["es"]["path"]
        key={"pk":"SLUG#test#thehairnarrative.com#es","sk":"PATH#"+path}
        self.ddb.before_commit=lambda d:d.row(self.public_table,key).update(publishedBundleKey="changed-by-another-writer")
        with self.assertRaises(EditorConflict): self.publish(revision="r2",operation="9"*32)
        self.assertNotIn("publishedRevisionId",self.article()["locales"]["en"])

    def test_unchanged_publish_cannot_succeed_if_live_manifest_is_not_available(self):
        from content_hub_v2_editor_model import EditorValidationError
        self.prepare();self.publish()
        self.ddb.row(METADATA_TABLE,{"pk":MANIFEST_PK,"sk":MANIFEST_SK})["publicationWriterEpoch"]=99
        with self.assertRaises(EditorValidationError): self.publish(operation="9"*32)

    def test_replay_never_returns_extra_private_fields_from_a_corrupt_receipt(self):
        from content_hub_v2_editor_model import EditorValidationError
        token=self.prepare();self.publish(token=token)
        receipt=next(r for r in self.ddb.items.values() if r.get("recordType")=="THN_CONTENT_HUB_V2_PUBLICATION_RECEIPT")
        receipt["result"]["privateField"]="must-not-be-returned"
        with self.assertRaises(EditorValidationError): self.publish(token=token)

    def test_automatic_allocation_resolves_collision_before_immutable_preparation(self):
        self.prepare(allocate=True);self.publish();self.unpublish()
        self.prepare(article="a2",allocate=True);self.publish(article="a2",operation="8"*32)
        self.assertTrue(self.article("a2")["locales"]["en"]["path"].endswith("/quiet-shape-2"))
        self.assertTrue(self.article("a1")["locales"]["en"]["path"].endswith("/quiet-shape"))

    def test_allocation_retry_has_stable_dates_and_no_new_public_data(self):
        token=self.prepare(allocate=True)
        first=self.store.allocate_publication(article_id="a1",locale="en",revision_id="r1",expected_token=token)
        before=deepcopy(self.ddb.items);self.now+=60
        second=self.store.allocate_publication(article_id="a1",locale="en",revision_id="r1",expected_token=token)
        self.assertEqual(first,second)
        self.assertEqual(self.ddb.items,before)
        self.assertEqual(len(self.public_rows()),1)

    def test_missing_head_page_cannot_be_extended_with_another_article(self):
        from content_hub_v2_editor_model import EditorValidationError
        from content_hub_v2_projection_manifest import ProjectionManifestError
        self.prepare();self.publish()
        self.ddb.items.pop(self.ddb.identity(METADATA_TABLE,{"pk":MANIFEST_PK,"sk":"PAGE#a1"}))
        self.prepare(article="a2",title="Another shape")
        before=deepcopy(self.ddb.items)
        with self.assertRaises((EditorValidationError,ProjectionManifestError)):
            self.publish(article="a2",operation="8"*32)
        self.assertEqual(self.ddb.items,before)

    def test_guard_factory_cannot_move_the_final_session_clock_backwards(self):
        from content_hub_v2_editor_model import EditorValidationError
        self.prepare();before=deepcopy(self.ddb.items);calls=0
        def guards():
            nonlocal calls
            calls+=1
            return [_condition_check(self.registry),*actor_condition_checks(self.auth,"a"*64,self.now if calls==1 else self.now-1)]
        self.store.guard_factory=guards
        with self.assertRaises(EditorValidationError): self.publish()
        self.assertEqual(self.ddb.items,before)

    def test_preparation_collection_race_preserves_previous_live_article(self):
        from content_hub_v2_editor_service import EditorConflict
        self.prepare();self.publish();self.now+=10;self.prepare(revision="r2")
        original=self.public_rows()
        prep_id="prep-"+_sha(_bytes(["a1","en","r2"]))
        self.ddb.before_commit=lambda d:d.row(METADATA_TABLE,{"pk":PREPARATION_PK,"sk":"PREPARATION#"+prep_id}).update(state="collecting")
        with self.assertRaises(EditorConflict): self.publish(revision="r2",operation="8"*32)
        self.assertEqual(self.public_rows(),original)
        self.assertEqual(self.article()["locales"]["en"]["publishedRevisionId"],"r1")

    def test_modified_private_package_never_reaches_the_final_transaction(self):
        from content_hub_v2_editor_model import EditorValidationError
        self.prepare();pointer=self.article()["locales"]["en"]["packagePointer"]
        self.s3.objects[self.private_bucket,pointer["key"]]["body"]=b'{"title":"tampered"}'
        before=deepcopy(self.ddb.items)
        with self.assertRaises(EditorValidationError): self.publish()
        self.assertEqual(self.ddb.items,before)
        self.assertFalse(any(operation=="transaction" for operation,_ in self.ddb.calls))

    def test_lost_success_response_replays_without_a_second_publication(self):
        token=self.prepare();original=self.ddb.transact_write_items
        def uncertain(**kwargs):
            original(**kwargs)
            raise TimeoutError("synthetic lost response")
        self.ddb.transact_write_items=uncertain
        with self.assertRaises(TimeoutError): self.publish(token=token)
        self.ddb.transact_write_items=original
        before=deepcopy(self.ddb.items)
        result=self.publish(token=token)
        self.assertEqual(result["state"],"published")
        self.assertEqual(self.ddb.items,before)
        self.assertEqual(sum(r.get("source")=="publication" for r in self.ddb.items.values()),1)

    def test_real_public_media_resolver_loses_addressability_on_unpublish(self):
        from types import SimpleNamespace
        from public_media_lambda import PublicMediaPath,PublicMediaNotFound,resolve_live_variant
        runtime=SimpleNamespace(load_live_manifest=lambda **key:self.ddb.row(self.public_table,
            {"pk":key["partition_key"],"sk":key["sort_key"]}))
        path=PublicMediaPath("a1","en","r1","m1","w768")
        self.prepare()
        with self.assertRaises(PublicMediaNotFound): resolve_live_variant(runtime,path)
        self.publish();value=resolve_live_variant(runtime,path)
        self.assertIn("/en/a1/r1/media/m1/",value.object_key)
        self.unpublish()
        with self.assertRaises(PublicMediaNotFound): resolve_live_variant(runtime,path)
        self.assertIn((self.delivery_bucket,value.object_key),self.s3.objects)

    @unittest.skipUnless(os.environ.get("THN_RUNTIME_READ_SOURCE"),"Select the approved local Runtime Read candidate")
    def test_actual_runtime_reader_consumes_committed_rows_and_keeps_locales_isolated(self):
        import test_content_hub_v2_runtime_contract as contract
        contract.OptInRuntimeContractTests.setUpClass()
        runtime=contract.OptInRuntimeContractTests.runtime
        self.prepare(locale="es");self.publish(locale="es")
        key={"pk":"HUB#thehairnarrative-com-journal","sk":"ARTICLE#a1"}
        row=self.ddb.row(self.public_table,key)
        self.assertIsNone(runtime._content_hub_article_summary(row,{"localePolicy":"published-only"},"en"))
        summary=runtime._content_hub_article_summary(row,{"localePolicy":"published-only"},"es")
        self.assertTrue(summary["path"].startswith("/the-journal/formas-nupciales/"))
        for field in ("pk","sk","itemFamily","hubId","publishedBundleKey","recordPurpose"):
            self.assertNotIn(field,summary)
        self.prepare(locale="en",revision="r2");self.publish(revision="r2",operation="8"*32)
        row=self.ddb.row(self.public_table,key)
        self.assertTrue(runtime._content_hub_article_summary(row,{"localePolicy":"published-only"},"en")["path"].startswith("/the-journal/bridal-forms/"))

    def test_allocation_race_retries_before_any_immutable_object_is_replaced(self):
        from content_hub_v2_editor_service import EditorConflict
        self.prepare()
        def concurrent_path(d):
            d.seed(METADATA_TABLE,{"pk":PARTITION_PREFIX+"PATHS#en","sk":"PATH#/the-journal/bridal-forms/quiet-shape",
                **THN_CURRENT_USER_SCOPE,"recordType":"THN_CONTENT_HUB_V2_PATH_RESERVATION","articleId":"other",
                "locale":"en","path":"/the-journal/bridal-forms/quiet-shape","recordPurpose":"client-owner"})
        # Use a new revision with no prepared objects to exercise pre-allocation.
        row=self.article();row["locales"]["en"]["workingRevisionId"]="r2";row["concurrencyToken"]="edit-r2"
        old_key=row["locales"]["en"]["packagePointer"]["key"]
        new_key=old_key.replace("/r1/","/r2/")
        row["locales"]["en"]["packagePointer"]["key"]=new_key
        self.s3.objects[self.private_bucket,new_key]=deepcopy(self.s3.objects[self.private_bucket,old_key])
        before=deepcopy(self.s3.objects)
        self.ddb.before_commit=concurrent_path
        with self.assertRaises(EditorConflict):
            self.store.allocate_publication(article_id="a1",locale="en",revision_id="r2",expected_token="edit-r2")
        selection=self.store.allocate_publication(article_id="a1",locale="en",revision_id="r2",expected_token="edit-r2")
        self.assertTrue(selection["path"].endswith("quiet-shape-2"))
        self.assertEqual(self.s3.objects,before)

    def test_full_twenty_inline_images_plus_cover_can_be_replaced_atomically(self):
        self.prepare(inline=[f"old{i}" for i in range(20)]);self.publish()
        self.now+=10
        self.prepare(revision="r2",asset="new-cover",inline=[f"new{i}" for i in range(20)])
        self.publish(revision="r2",operation="8"*32)
        transaction=[kwargs for operation,kwargs in self.ddb.calls if operation=="transaction"][-1]
        self.assertLessEqual(len(transaction["TransactItems"]),90)
        self.assertEqual(len(self.article()["locales"]["en"]["publishedAssetIds"]),21)
        old=self.ddb.row(METADATA_TABLE,{"pk":PARTITION_PREFIX+"ASSETS#a1#en","sk":"ASSET#m1"})
        new=self.ddb.row(METADATA_TABLE,{"pk":PARTITION_PREFIX+"ASSETS#a1#en","sk":"ASSET#new-cover"})
        self.assertEqual((old["referenceCount"],new["referenceCount"]),(0,2))


if __name__=="__main__":unittest.main()
