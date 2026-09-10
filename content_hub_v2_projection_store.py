"""Exact-key private preparation adapter for the dedicated THN publisher.

SDK clients and server-resolved bucket names are injected. This adapter cannot
write a public metadata table or make prepared objects addressable.
"""
from copy import deepcopy
from types import SimpleNamespace
import re

from content_hub_v2_actor_fence import actor_condition_checks, SCOPE_ATTRIBUTES
from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE
from content_hub_v2_editor_model import EditorValidationError, safe_id, safe_locale
from content_hub_v2_preparation import SOURCE_ROOT, MAX_OBJECT_BYTES, _bytes, _sha, _version
from content_hub_v2_projection import ROOT, EXTENSIONS, VARIANTS, bundle_key
from content_hub_v2_registry_fence import _condition_check, marshal_item, unmarshal_item

METADATA_TABLE = "zoolanding-content-hub-test-ThnContentHubV2Metadata"
PARTITION = "THN#test#thehairnarrative.com#journal-owner#thehairnarrative-com#thehairnarrative-com-journal#PREPARATION"
INTENT_FIELDS = set(THN_CURRENT_USER_SCOPE)|{"articleId","locale","revisionId","recordPurpose","objects",
    "preparationId","recordType","schemaVersion","intentDigest","candidateAtEpoch","state"}


def _reject(code="preparation_unavailable"):
    raise EditorValidationError(code)


def _error_code(error):
    return getattr(error,"response",{}).get("Error",{}).get("Code")


class AwsPreparationStore:
    def __init__(self,*,dynamodb,s3,account_id,region,source_bucket,delivery_bucket,guard_factory):
        if (not isinstance(account_id,str) or re.fullmatch(r"[0-9]{12}",account_id) is None
                or not isinstance(region,str) or re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]",region) is None
                or source_bucket!=f"zlp-thn-private-upload-test-{account_id}-{region}"
                or not isinstance(delivery_bucket,str) or re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]",delivery_bucket) is None
                or delivery_bucket==source_bucket or not callable(guard_factory)):
            _reject("invalid_publication_binding")
        self.ddb,self.s3=dynamodb,s3
        self.source_bucket,self.delivery_bucket=source_bucket,delivery_bucket
        self.guard_factory=guard_factory
        self.intent=None
        self.expected={}
        self.receipts={}

    def _guards(self,purpose=None):
        guards=self.guard_factory()
        try:
            if not isinstance(guards,list) or len(guards)!=3 or any(set(g)!={"ConditionCheck"} for g in guards):
                _reject()
            registry_values=unmarshal_item(guards[0]["ConditionCheck"]["ExpressionAttributeValues"])
            registry={key[1:]:value for key,value in registry_values.items()}
            if guards[0]!=_condition_check(registry) or any(registry.get(k)!=v for k,v in THN_CURRENT_USER_SCOPE.items()):
                _reject()
            bound_table=registry["resourceBindings"].get("metadataTableArn")
            if not isinstance(bound_table,str) or not bound_table.endswith(":table/"+METADATA_TABLE):
                _reject("invalid_publication_binding")
            values=unmarshal_item(guards[2]["ConditionCheck"]["ExpressionAttributeValues"])
            session_hash=unmarshal_item(guards[2]["ConditionCheck"]["Key"])["sessionIdHash"]
            actor=SimpleNamespace(subject=values[":subject"],account_purpose=values[":purpose"],
                session_version=values[":version"],**{attr:THN_CURRENT_USER_SCOPE[key] for key,attr in SCOPE_ATTRIBUTES.items()})
            if guards[1:]!=actor_condition_checks(actor,session_hash,values[":now"]):
                _reject()
            if (registry.get("activationStatus")!="active" or type(registry.get("writerEpoch")) is not int
                    or registry["writerEpoch"]<1 or registry.get("writerMode")!={"qa":"qa-only","client-owner":"client-owner"}[actor.account_purpose]
                    or (purpose is not None and actor.account_purpose!=purpose)):
                _reject()
        except (KeyError,TypeError,ValueError,AttributeError):
            _reject("invalid_publication_authority")
        return deepcopy(guards)

    @staticmethod
    def _validate_intent(intent):
        if not isinstance(intent,dict) or set(intent)!=INTENT_FIELDS:
            _reject()
        article,locale,revision=safe_id(intent["articleId"]),safe_locale(intent["locale"]),safe_id(intent["revisionId"])
        if (any(intent.get(k)!=v for k,v in THN_CURRENT_USER_SCOPE.items())
                or intent["recordPurpose"] not in {"qa","client-owner"}
                or intent["recordType"]!="THN_CONTENT_HUB_V2_PREPARATION"
                or type(intent["schemaVersion"]) is not int or intent["schemaVersion"]!=1
                or intent["state"]!="preparing" or type(intent["candidateAtEpoch"]) is not int or intent["candidateAtEpoch"]<0
                or intent["preparationId"]!="prep-"+_sha(_bytes([article,locale,revision]))):
            _reject()
        objects=intent["objects"]
        if not isinstance(objects,list) or not 5<=len(objects)<=85:
            _reject()
        bundle_count=0;variants={};keys=[]
        for spec in objects:
            if (not isinstance(spec,dict) or set(spec)!={"key","contentType","bytes","sha256"}
                    or not isinstance(spec["key"],str) or type(spec["bytes"]) is not int or not 0<spec["bytes"]<=MAX_OBJECT_BYTES
                    or not isinstance(spec["sha256"],str) or re.fullmatch(r"[a-f0-9]{64}",spec["sha256"]) is None):
                _reject()
            keys.append(spec["key"])
            if spec["key"]==bundle_key(article,locale,revision) and spec["contentType"]=="application/json":
                bundle_count+=1
            else:
                extension=EXTENSIONS.get(spec["contentType"])
                if not extension: _reject()
                match=re.fullmatch(re.escape(f"{ROOT}/{locale}/{article}/{revision}/media/")
                    +r"([A-Za-z0-9][A-Za-z0-9_-]{0,79})/(w480|w768|w1200|w1600)"
                    +re.escape("."+extension),spec["key"])
                if not match: _reject()
                variants.setdefault(match[1],set()).add(match[2])
        material={k:v for k,v in intent.items() if k in set(THN_CURRENT_USER_SCOPE)|{
            "articleId","locale","revisionId","recordPurpose","objects"}}
        if (len(keys)!=len(set(keys)) or bundle_count!=1 or any(v!=set(VARIANTS) for v in variants.values())
                or intent["intentDigest"]!=_sha(_bytes(material))):
            _reject()
        return deepcopy(intent)

    def begin_preparation(self,intent):
        intent=self._validate_intent(intent)
        self._guards(intent["recordPurpose"])
        key={"pk":PARTITION,"sk":"PREPARATION#"+intent["preparationId"]}
        response=self.ddb.get_item(TableName=METADATA_TABLE,Key=marshal_item(key),ConsistentRead=True)
        old=unmarshal_item(response["Item"]) if response.get("Item") else None
        if not old:
            row={**key,"intent":intent,"state":"preparing","receipts":{}}
            try:
                self.ddb.transact_write_items(TransactItems=[*self._guards(intent["recordPurpose"]),
                    {"Put":{"TableName":METADATA_TABLE,"Item":marshal_item(row),"ConditionExpression":"attribute_not_exists(pk)"}}])
                old=row
            except Exception as error:
                if _error_code(error)!="TransactionCanceledException": raise
                self._guards(intent["recordPurpose"])
                response=self.ddb.get_item(TableName=METADATA_TABLE,Key=marshal_item(key),ConsistentRead=True)
                old=unmarshal_item(response["Item"]) if response.get("Item") else None
        if (not isinstance(old,dict) or set(old)!={"pk","sk","intent","state","receipts"}
                or old.get("pk")!=key["pk"] or old.get("sk")!=key["sk"] or old.get("state")!="preparing"
                or not isinstance(old.get("receipts"),dict)):
            _reject("preparation_conflict")
        existing=self._validate_intent(old["intent"])
        if any(existing[k]!=v for k,v in intent.items() if k!="candidateAtEpoch") or existing["candidateAtEpoch"]>intent["candidateAtEpoch"]:
            _reject("preparation_conflict")
        self.intent=existing
        self.expected={spec["key"]:spec for spec in existing["objects"]}
        self.receipts=deepcopy(old["receipts"])
        for object_id,receipt in self.receipts.items():
            self._receipt(receipt)
            if object_id!=_sha(receipt["key"].encode()): _reject("invalid_prepared_receipt")
        self._guards(existing["recordPurpose"])
        return deepcopy(existing)

    def _active(self):
        if self.intent is None: _reject("preparation_not_reserved")
        return self._guards(self.intent["recordPurpose"])

    def _receipt(self,receipt):
        if (not isinstance(receipt,dict) or set(receipt)!={"key","contentType","bytes","sha256","versionId"}
                or receipt["key"] not in self.expected or type(receipt["bytes"]) is not int
                or any(receipt[k]!=v for k,v in self.expected[receipt["key"]].items())):
            _reject("invalid_prepared_receipt")
        _version(receipt["versionId"])

    def read_private_variant(self,pointer):
        self._active()
        if not isinstance(pointer,dict) or set(pointer)!={"key","versionId","contentType","bytes","sha256"}:
            _reject()
        _version(pointer["versionId"])
        article,locale=self.intent["articleId"],self.intent["locale"]
        extension=EXTENSIONS.get(pointer["contentType"])
        if not extension or not isinstance(pointer["key"],str): _reject()
        match=re.fullmatch(re.escape(f"{SOURCE_ROOT}{article}/{locale}/revisions/")
            +r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}/assets/([A-Za-z0-9][A-Za-z0-9_-]{0,79})/(w480|w768|w1200|w1600)"
            +re.escape("."+extension),pointer["key"])
        if not match: _reject()
        destination=f"{ROOT}/{locale}/{article}/{self.intent['revisionId']}/media/{match[1]}/{match[2]}.{extension}"
        spec=self.expected.get(destination,{})
        if any(pointer.get(k)!=spec.get(k) for k in ("bytes","contentType","sha256")): _reject()
        response=self.s3.get_object(Bucket=self.source_bucket,Key=pointer["key"],VersionId=pointer["versionId"])
        if response.get("VersionId")!=pointer["versionId"] or response.get("ContentType")!=pointer["contentType"] or response.get("ContentLength")!=pointer["bytes"]:
            response["Body"].close();_reject("image_integrity_failed")
        return response["Body"]

    def put_prepared_object(self,spec,body):
        self._active()
        if (not isinstance(spec,dict) or spec!=self.expected.get(spec.get("key"))
                or not isinstance(body,bytes) or len(body)!=spec["bytes"] or _sha(body)!=spec["sha256"]):
            _reject("invalid_prepared_object")
        try:
            response=self.s3.put_object(Bucket=self.delivery_bucket,Key=spec["key"],Body=body,
                ContentType=spec["contentType"],CacheControl="private,no-store",ServerSideEncryption="AES256",IfNoneMatch="*")
            version=_version(response.get("VersionId"))
        except Exception as error:
            if _error_code(error) not in {"PreconditionFailed","412"}: raise
            self._active()
            response=self.s3.get_object(Bucket=self.delivery_bucket,Key=spec["key"])
            try:
                existing=response["Body"].read(MAX_OBJECT_BYTES+1)
            finally:
                response["Body"].close()
            if (response.get("ContentType")!=spec["contentType"] or len(existing)!=spec["bytes"]
                    or _sha(existing)!=spec["sha256"]):
                _reject("immutable_object_conflict")
            version=_version(response.get("VersionId"))
        return {**deepcopy(spec),"versionId":version}

    def record_prepared_object(self,preparation_id,receipt):
        guards=self._active()
        self._receipt(receipt)
        if preparation_id!=self.intent["preparationId"]: _reject()
        object_id=_sha(receipt["key"].encode())
        prior=self.receipts.get(object_id)
        if prior is not None and prior!=receipt: _reject("preparation_conflict")
        try:
            self.ddb.transact_write_items(TransactItems=[*guards,{"Update":{
                "TableName":METADATA_TABLE,"Key":marshal_item({"pk":PARTITION,"sk":"PREPARATION#"+preparation_id}),
                "UpdateExpression":"SET receipts.#object = :receipt",
                "ConditionExpression":"#state = :preparing AND intent.intentDigest = :digest AND (attribute_not_exists(receipts.#object) OR receipts.#object = :receipt)",
                "ExpressionAttributeNames":{"#state":"state","#object":object_id},
                "ExpressionAttributeValues":marshal_item({":preparing":"preparing",":digest":self.intent["intentDigest"],":receipt":receipt})}}])
        except Exception as error:
            if _error_code(error)=="TransactionCanceledException": _reject("preparation_conflict")
            raise
        self.receipts[object_id]=deepcopy(receipt)
