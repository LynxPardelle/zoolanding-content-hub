"""Publication preparation is private, exact-key and restartable."""
from copy import deepcopy
import hashlib
import importlib
import io
import json
import unittest
from unittest.mock import Mock
from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE
from content_hub_v2_editor_model import EditorValidationError
from content_hub_v2_private_upload import private_variant_key


class MemoryPreparationStore:
    def __init__(self):
        self.sources = {}
        self.objects = {}
        self.intents = {}
        self.receipts = {}
        self.calls = []
        self.fail_after = None

    def begin_preparation(self, intent):
        self.calls.append(("begin", intent["preparationId"]))
        old = self.intents.get(intent["preparationId"])
        if old and old["intentDigest"] != intent["intentDigest"]:
            raise EditorValidationError("preparation_conflict")
        self.intents.setdefault(intent["preparationId"], deepcopy(intent))
        return deepcopy(self.intents[intent["preparationId"]])

    def read_private_variant(self, pointer):
        self.calls.append(("read", pointer["key"], pointer["versionId"]))
        return io.BytesIO(self.sources[pointer["key"],pointer["versionId"]])

    def put_prepared_object(self, spec, body):
        self.calls.append(("put", spec["key"]))
        if self.fail_after is not None and len(self.objects) >= self.fail_after:
            raise RuntimeError("synthetic storage failure")
        old = self.objects.get(spec["key"])
        if old and old["body"] != body:
            raise EditorValidationError("immutable_object_conflict")
        self.objects.setdefault(spec["key"], {"body":body,"receipt":{**spec,"versionId":"v"+str(len(self.objects)+1)}})
        return deepcopy(self.objects[spec["key"]]["receipt"])

    def record_prepared_object(self, preparation_id, receipt):
        self.calls.append(("record",receipt["key"]))
        self.receipts.setdefault(preparation_id,{})[receipt["key"]] = deepcopy(receipt)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.p = importlib.import_module("content_hub_v2_preparation")
        self.store = MemoryPreparationStore()
        self.package = {"title":"Quiet shape","summary":"A short observation.","seriesId":"bridal-forms","tags":["private"],
                        "cover":{"assetId":"m1","alt":"Soft hair","focalX":40,"focalY":60},
                        "delta":{"ops":[{"insert":"A quiet observation.\n"}]}}
        variants=[]
        for variant_id in ("w480","w768","w1200","w1600"):
            body=("synthetic-image-"+variant_id).encode()
            variant={"variantId":variant_id,"contentType":"image/webp","bytes":len(body),
                     "sha256":hashlib.sha256(body).hexdigest(),"versionId":"source-version",
                     "width":100,"height":100}
            variant["key"]=private_variant_key({"articleId":"a1","locale":"en","revisionId":"r0","assetId":"m1"},variant)
            variants.append(variant)
            self.store.sources[variant["key"],variant["versionId"]]=body
        self.assets={"m1":{**THN_CURRENT_USER_SCOPE,"articleId":"a1","locale":"en","assetId":"m1","status":"ready",
                           "recordPurpose":"client-owner","referenceCount":1,"deliveryState":"private",
                           "alt":"Soft hair","variants":variants}}
        self.kwargs=dict(article_id="a1",locale="en",revision_id="r1",package=self.package,assets=self.assets,
                         path="/the-journal/bridal-forms/quiet-shape",first_published_at="2026-09-08T00:00:00Z",
                         updated_at="2026-09-08T00:00:00Z",purpose="client-owner",now_epoch=1788840000,
                         store=self.store,authorize=lambda:None)

    def prepare(self, **kwargs):
        return self.p.prepare_immutable_objects(**{**self.kwargs,**kwargs})

    def test_exact_versioned_variants_and_generated_bundle_are_prepared_but_not_activated(self):
        result=self.prepare()
        self.assertEqual(len(self.store.objects),5)
        self.assertEqual(self.store.calls[0][0],"begin")
        self.assertEqual(len(result["deliveryManifest"]["variants"]),4)
        self.assertEqual(len(result["objects"]),5)
        bundle=json.loads(self.store.objects[result["bundlePointer"]["key"]]["body"])
        self.assertEqual(bundle["variables"]["articleContent"]["html"],"<p>A quiet observation.</p>")
        self.assertNotIn("private",json.dumps(bundle))
        self.assertEqual(result["preparation"]["state"],"prepared")
        self.assertEqual(result["preparation"]["candidateAtEpoch"],self.kwargs["now_epoch"])
        self.assertNotIn("publish", [c[0] for c in self.store.calls])
        self.assertFalse(hasattr(self.store,"put_live_manifest"))

    def test_same_input_retry_reuses_versions_and_preserves_original_candidate_age(self):
        first=self.prepare()
        second=self.prepare(now_epoch=self.kwargs["now_epoch"]+200)
        self.assertEqual(first,second)
        self.assertEqual(len(self.store.objects),5)
        self.assertEqual(len(self.store.intents),1)

    def test_all_source_metadata_is_checked_before_storage_access(self):
        for mutate in (
            lambda a:a["m1"].update(recordPurpose="qa"),
            lambda a:a["m1"].update(domain="zoositioweb.com.mx"),
            lambda a:a["m1"].update(status="collecting"),
            lambda a:a["m1"].update(referenceCount=0),
            lambda a:a["m1"]["variants"][0].update(key="outside/secret"),
            lambda a:a["m1"]["variants"][0].update(versionId="null"),
            lambda a:a["m1"]["variants"].pop(),
            lambda a:a["m1"]["variants"].append(deepcopy(a["m1"]["variants"][0])),
        ):
            assets=deepcopy(self.assets); mutate(assets)
            with self.assertRaises(EditorValidationError):
                self.prepare(assets=assets)
            self.assertEqual(self.store.calls,[])

    def test_source_digest_failure_never_returns_a_delivery_manifest(self):
        pointer=self.assets["m1"]["variants"][0]
        self.store.sources[pointer["key"],pointer["versionId"]]=b"tampered"
        with self.assertRaises(EditorValidationError):
            self.prepare()
        self.assertEqual(len(self.store.intents),1)
        self.assertEqual(self.store.objects,{})

    def test_partial_write_keeps_exact_cleanup_intent_and_resumes_privately(self):
        self.store.fail_after=2
        with self.assertRaises(RuntimeError):
            self.prepare()
        self.assertEqual(len(self.store.objects),2)
        intent=next(iter(self.store.intents.values()))
        self.assertEqual(len(intent["objects"]),5)
        self.assertEqual(len(self.store.receipts[intent["preparationId"]]),2)
        self.store.fail_after=None
        result=self.prepare()
        self.assertEqual(len(result["objects"]),5)
        self.assertEqual(result["preparation"]["preparationId"],intent["preparationId"])

    def test_authority_change_stops_before_another_prepared_write(self):
        checks=Mock(side_effect=[None,None,EditorValidationError("auth_required")])
        with self.assertRaises(EditorValidationError):
            self.prepare(authorize=checks)
        self.assertEqual(self.store.objects,{})

    def test_changed_package_cannot_overwrite_an_immutable_revision(self):
        self.prepare()
        package=deepcopy(self.package);package["summary"]="Different summary."
        with self.assertRaises(EditorValidationError):
            self.prepare(package=package)
        self.assertEqual(len(self.store.objects),5)

    def test_corrupt_storage_receipt_or_candidate_is_not_accepted(self):
        self.store.put_prepared_object=Mock(return_value={"key":"outside","versionId":"null"})
        with self.assertRaises(EditorValidationError):
            self.prepare()
        self.assertEqual(self.store.receipts,{})

    def test_invalid_preparation_clock_scope_and_store_checkpoint_fail_closed(self):
        for kwargs in ({"now_epoch":True},{"now_epoch":-1},{"purpose":"qa"},{"assets":None},
                       {"article_id":"../outside"},{"locale":"fr"}):
            with self.assertRaises(EditorValidationError):
                self.prepare(**kwargs)
            self.assertEqual(self.store.calls,[])
        self.store.begin_preparation=Mock(side_effect=lambda value:{**value,"schemaVersion":True})
        with self.assertRaises(EditorValidationError):
            self.prepare()
        self.assertEqual(self.store.objects,{})


if __name__ == "__main__": unittest.main()
