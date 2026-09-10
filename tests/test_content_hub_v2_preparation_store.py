"""Real preparation adapter exercised only against bounded storage doubles."""
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import unittest
from unittest.mock import Mock
from botocore.exceptions import ClientError
from content_hub_v2_registry_fence import marshal_item, unmarshal_item
import test_content_hub_v2_preparation as preparation_fixtures
from test_content_hub_v2_authorization import FakeAuthorizationStore, REGISTRY
from content_hub_v2_authorization import load_authorization_context
from content_hub_v2_actor_fence import actor_condition_checks
from content_hub_v2_registry_fence import _condition_check
from tests.test_service_binding_registry_v2 import build_record, registry_definition
from content_hub_v2_editor_model import EditorValidationError


class ExactS3:
    def __init__(self):
        self.objects={}; self.calls=[]
    def put_object(self,**kw):
        self.calls.append(("put",kw))
        key=(kw["Bucket"],kw["Key"])
        if kw.get("IfNoneMatch")!="*": raise AssertionError("immutable write required")
        if key in self.objects: raise ClientError({"Error":{"Code":"PreconditionFailed"}},"PutObject")
        value={"VersionId":"v"+str(len(self.objects)+1),"ContentType":kw["ContentType"],
               "body":kw["Body"]}
        self.objects[key]=value
        return {"VersionId":value["VersionId"]}
    def get_object(self,**kw):
        self.calls.append(("get",kw))
        value=self.objects[kw["Bucket"],kw["Key"]]
        if "VersionId" in kw and kw["VersionId"]!=value["VersionId"]:
            raise ClientError({"Error":{"Code":"NoSuchVersion"}},"GetObject")
        return {"Body":io.BytesIO(value["body"]),"ContentLength":len(value["body"]),
                "ContentType":value["ContentType"],"VersionId":value["VersionId"]}


class ExactMetadata:
    def __init__(self):
        self.item=None;self.calls=[]
    def get_item(self,**kw):
        self.calls.append(("get",kw))
        return {"Item":marshal_item(self.item)} if self.item else {}
    def transact_write_items(self,**kw):
        self.calls.append(("transaction",kw))
        mutation=kw["TransactItems"][-1]
        if "Put" in mutation:
            if self.item: raise ClientError({"Error":{"Code":"TransactionCanceledException"}},"TransactWriteItems")
            self.item=unmarshal_item(mutation["Put"]["Item"])
        elif "Update" in mutation:
            fields=mutation["Update"]
            values=unmarshal_item(fields["ExpressionAttributeValues"])
            object_id=fields["ExpressionAttributeNames"]["#object"]
            old=self.item["receipts"].get(object_id)
            if old and old!=values[":receipt"]:
                raise ClientError({"Error":{"Code":"TransactionCanceledException"}},"TransactWriteItems")
            self.item["receipts"][object_id]=deepcopy(values[":receipt"])
        return {}


class PreparationAdapterTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("content_hub_v2_projection_store"),
                             "the production preparation storage adapter is not implemented")
        self.module=__import__("content_hub_v2_projection_store")
        self.fixture=preparation_fixtures.PreparationTests();self.fixture.setUp()
        self.ddb=ExactMetadata();self.s3=ExactS3()
        auth=load_authorization_context(FakeAuthorizationStore(),session_id_hash="a"*64,registry_record=REGISTRY,now_epoch=1000)
        registry=build_record(registry_definition(activationStatus="active",writerMode="client-owner",writerEpoch=7,registryRevision=3))
        self.guards=[_condition_check(registry),*actor_condition_checks(auth,"a"*64,1000)]
        self.source_bucket="zlp-thn-private-upload-test-000000000000-us-east-1"
        self.delivery_bucket="fixture-thn-published-packages"
        self.args=dict(dynamodb=self.ddb,s3=self.s3,account_id="000000000000",region="us-east-1",
                       source_bucket=self.source_bucket,delivery_bucket=self.delivery_bucket,
                       guard_factory=lambda:deepcopy(self.guards))
        self.store=self.module.AwsPreparationStore(**self.args)
        for (key,version),body in self.fixture.store.sources.items():
            self.s3.objects[self.source_bucket,key]={"VersionId":version,"ContentType":"image/webp","body":body}

    def prepare(self,store=None,**overrides):
        return self.fixture.prepare(store=store or self.store,**overrides)

    def test_real_adapter_creates_versioned_objects_and_durable_exact_receipts(self):
        result=self.prepare()
        writes=[kw for op,kw in self.s3.calls if op=="put"]
        self.assertEqual(len(writes),5)
        self.assertTrue(all(w["IfNoneMatch"]=="*" and w["ServerSideEncryption"]=="AES256" for w in writes))
        self.assertTrue(all(w["Bucket"]==self.delivery_bucket and w["CacheControl"]=="private,no-store" for w in writes))
        self.assertEqual(len(self.ddb.item["receipts"]),5)
        transactions=[kw["TransactItems"] for op,kw in self.ddb.calls if op=="transaction"]
        self.assertEqual(len(transactions),6)
        self.assertTrue(all(tx[:3]==self.guards for tx in transactions))
        self.assertEqual(self.ddb.item["state"],"preparing")
        self.assertEqual(self.ddb.item["intent"]["state"],"preparing")
        self.assertEqual(result["bundlePointer"]["versionId"],"v9")

    def test_retry_in_a_new_instance_reuses_versions_and_original_age(self):
        first=self.prepare()
        second=self.prepare(store=self.module.AwsPreparationStore(**self.args),now_epoch=self.fixture.kwargs["now_epoch"]+60)
        self.assertEqual(first,second)
        self.assertEqual(len(self.s3.objects),9)

    def test_read_never_uses_unversioned_private_source(self):
        self.prepare()
        reads=[kw for op,kw in self.s3.calls if op=="get" and kw["Bucket"]==self.source_bucket]
        self.assertEqual(len(reads),4)
        self.assertTrue(all(kw["VersionId"]=="source-version" for kw in reads))

    def test_rejected_registry_or_actor_guard_cannot_write_objects(self):
        denied=Mock(side_effect=EditorValidationError("auth_required"))
        with self.assertRaises(EditorValidationError):
            self.prepare(store=self.module.AwsPreparationStore(**{**self.args,"guard_factory":denied}))
        self.assertFalse(any(op=="put" for op,_ in self.s3.calls))

    def test_dedicated_source_binding_cannot_point_to_another_bucket(self):
        with self.assertRaises(EditorValidationError):
            self.module.AwsPreparationStore(**{**self.args,"source_bucket":"some-other-draft"})
        with self.assertRaises(EditorValidationError):
            self.module.AwsPreparationStore(**{**self.args,"delivery_bucket":self.source_bucket})

    def test_no_object_write_is_allowed_without_a_reserved_intent(self):
        with self.assertRaises(EditorValidationError):
            self.store.put_prepared_object({"key":"outside","sha256":"a"*64,"bytes":1,"contentType":"image/png"},b"x")
        self.assertEqual(self.s3.calls,[])

    def test_preexisting_different_object_is_not_overwritten_or_accepted(self):
        original_put=self.s3.put_object
        def put(**kw):
            self.s3.objects[kw["Bucket"],kw["Key"]]={"VersionId":"other-version","ContentType":kw["ContentType"],"body":b"wrong"}
            return original_put(**kw)
        self.s3.put_object=put
        with self.assertRaises(EditorValidationError):
            self.prepare()
        self.assertEqual(self.ddb.item["receipts"],{})

    def test_receipt_conflict_and_collector_claim_stop_a_retry(self):
        self.prepare()
        self.ddb.item["state"]="collecting"
        with self.assertRaises(EditorValidationError):
            self.prepare(store=self.module.AwsPreparationStore(**self.args))
        self.ddb.item["state"]="preparing"
        first_key=next(iter(self.ddb.item["receipts"]))
        self.ddb.item["receipts"][first_key]["versionId"]="conflicting-version"
        with self.assertRaises(EditorValidationError):
            self.prepare(store=self.module.AwsPreparationStore(**self.args))

    def test_guards_cannot_be_omitted_or_misrouted(self):
        for guards in ([],self.guards[:1],[{"Put":{"TableName":"other","Item":{}}}],list(reversed(self.guards))):
            with self.assertRaises(EditorValidationError):
                self.prepare(store=self.module.AwsPreparationStore(**{**self.args,"guard_factory":lambda:guards}))
        self.assertFalse(any(op=="put" for op,_ in self.s3.calls))

    def test_failed_receipt_transaction_resumes_without_overwriting_the_private_object(self):
        original=self.ddb.transact_write_items
        failed=False
        def transact(**kwargs):
            nonlocal failed
            if not failed and "Update" in kwargs["TransactItems"][-1]:
                failed=True
                raise ClientError({"Error":{"Code":"TransactionCanceledException"}},"TransactWriteItems")
            return original(**kwargs)
        self.ddb.transact_write_items=transact
        with self.assertRaises(EditorValidationError): self.prepare()
        self.assertEqual(self.ddb.item["receipts"],{})
        self.assertEqual(self.ddb.item["state"],"preparing")
        self.assertEqual(len(self.ddb.item["intent"]["objects"]),5)
        saved={key:deepcopy(value) for key,value in self.s3.objects.items() if key[0]==self.delivery_bucket}
        self.assertEqual(len(saved),1)
        result=self.prepare(store=self.module.AwsPreparationStore(**self.args))
        self.assertEqual(len(result["objects"]),5)
        for key,value in saved.items(): self.assertEqual(self.s3.objects[key],value)
        for operation,kwargs in self.ddb.calls:
            if operation!="transaction": continue
            mutation=kwargs["TransactItems"][-1]
            details=next(iter(mutation.values()))
            self.assertEqual(details["TableName"],self.module.METADATA_TABLE)
            target=unmarshal_item(details.get("Item",details.get("Key")))
            self.assertEqual(target["pk"],self.module.PARTITION)

    def test_registry_cannot_bind_preparation_to_another_metadata_table(self):
        values=self.guards[0]["ConditionCheck"]["ExpressionAttributeValues"]
        bindings=unmarshal_item({"value":values[":resourceBindings"]})["value"]
        bindings["metadataTableArn"]="arn:aws:dynamodb:us-east-1:000000000000:table/another-draft"
        values[":resourceBindings"]=marshal_item({"value":bindings})["value"]
        with self.assertRaises(EditorValidationError): self.prepare()
        self.assertFalse(any(operation=="put" for operation,_ in self.s3.calls))


if __name__=="__main__":unittest.main()
