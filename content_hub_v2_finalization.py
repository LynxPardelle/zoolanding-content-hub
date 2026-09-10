"""Atomic THN-only publication adapter; no Lambda entrypoint or default clients.

The caller supplies server-resolved bindings and fresh registry/actor/session
guards. All content is loaded from pinned private packages, never from a browser
payload. This candidate is local-only until publisher/IAM/release gates pass.
"""
from copy import deepcopy
from datetime import datetime,timezone
import json
import re
from types import SimpleNamespace

from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE
from content_hub_v2_editor_model import (EditorValidationError,MAX_PACKAGE_BYTES,normalize_package,
    referenced_assets,safe_id,safe_locale,article_path)
from content_hub_v2_editor_model import EditorConflict
from content_hub_v2_state_keys import METADATA_TABLE,AUDIT_TABLE,ARTICLE_PK,PARTITION_PREFIX,PRIVATE_PREFIX
from content_hub_v2_preparation import _bytes,_sha,_version,_source_variants,MAX_OBJECT_BYTES
from content_hub_v2_projection import (build_locale_projection,build_delivery_manifest,bundle_key,
    build_article_index_item,build_category_items,build_slug_pointer)
from content_hub_v2_projection_delta import build_projection_delta
from content_hub_v2_projection_store import AwsPreparationStore,PARTITION as PREPARATION_PK
from content_hub_v2_registry_fence import marshal_item,unmarshal_item
from content_hub_v2_actor_fence import USER_TABLE,SESSION_TABLE
from content_hub_v2_manifest_update import update_manifest,check_live_membership

OPERATION_PK=PARTITION_PREFIX+"PUBLICATION"


def _reject(code="publication_unavailable"):
    raise EditorValidationError(code)


class _Transaction:
    """Coalesce exact-key reads and mutations into one compare-and-swap batch."""
    def __init__(self,client):
        self.client=client;self.rows={}

    @staticmethod
    def identity(table,key):
        return table,tuple(sorted(key.items()))

    def expect(self,table,key,before):
        identity=self.identity(table,key)
        if before is not None and any(before.get(k)!=v for k,v in key.items()): _reject()
        if identity in self.rows and self.rows[identity][0]!=before: raise EditorConflict()
        self.rows.setdefault(identity,[deepcopy(before),deepcopy(before),False])

    def read(self,table,key):
        identity=self.identity(table,key)
        if identity not in self.rows:
            response=self.client.get_item(TableName=table,Key=marshal_item(key),ConsistentRead=True)
            self.expect(table,key,unmarshal_item(response["Item"]) if response.get("Item") else None)
        return deepcopy(self.rows[identity][0])

    def put(self,table,item):
        key={k:item[k] for k in ("pk","sk")}
        if len(_bytes(item))>350_000: _reject("publication_limit")
        if self.identity(table,key) not in self.rows: self.read(table,key)
        self.rows[self.identity(table,key)][1:]=[deepcopy(item),True]

    def delete(self,table,key):
        if self.identity(table,key) not in self.rows: self.read(table,key)
        self.rows[self.identity(table,key)][1:]=[None,True]

    def items(self):
        result=[]
        for (table,key_fields),(before,after,mutated) in sorted(self.rows.items()):
            key=dict(key_fields)
            details={"TableName":table,"Key":marshal_item(key)}
            if before is None:
                details.update(ConditionExpression="attribute_not_exists(#pk)",ExpressionAttributeNames={"#pk":"pk"})
            else:
                fields=sorted(before)
                details.update(ConditionExpression=" AND ".join(f"#f{i} = :v{i}" for i in range(len(fields))),
                    ExpressionAttributeNames={f"#f{i}":field for i,field in enumerate(fields)},
                    ExpressionAttributeValues=marshal_item({f":v{i}":before[field] for i,field in enumerate(fields)}))
            if not mutated or before==after:
                result.append({"ConditionCheck":details})
            elif after is None:
                result.append({"Delete":details})
            else:
                details.pop("Key");details["Item"]=marshal_item(after)
                result.append({"Put":details})
        return result


class AwsPublicationStore(AwsPreparationStore):
    def __init__(self,*,private_bucket,public_table,**kwargs):
        super().__init__(**kwargs)
        if (private_bucket!=f"zlp-thn-ch-test-private-{kwargs['account_id']}-{kwargs['region']}"
                or not isinstance(public_table,str) or re.fullmatch(r"[A-Za-z0-9_.-]{3,255}",public_table) is None
                or public_table in {METADATA_TABLE,AUDIT_TABLE,USER_TABLE,SESSION_TABLE,
                    "zoolanding-content-hub-test-ServiceBindingRegistryV2"}
                or private_bucket==self.delivery_bucket):
            _reject("invalid_publication_binding")
        self.private_bucket,self.public_table=private_bucket,public_table

    def _json(self,bucket,pointer,limit):
        if not isinstance(pointer,dict) or set(pointer)!={"key","versionId","sha256"}: _reject()
        _version(pointer["versionId"])
        if not isinstance(pointer["sha256"],str) or re.fullmatch(r"[a-f0-9]{64}",pointer["sha256"]) is None: _reject()
        response=self.s3.get_object(Bucket=bucket,Key=pointer["key"],VersionId=pointer["versionId"])
        try: body=response["Body"].read(limit+1)
        finally: response["Body"].close()
        if (not isinstance(body,bytes) or len(body)>limit or _sha(body)!=pointer["sha256"]
                or response.get("VersionId")!=pointer["versionId"] or response.get("ContentType")!="application/json"):
            _reject("publication_integrity_failed")
        try: return json.loads(body)
        except (ValueError,UnicodeDecodeError): _reject("publication_integrity_failed")

    def _prepared(self,tx,article,locale,revision,purpose,cache):
        identity=article,locale,revision
        if identity in cache: return cache[identity]
        prep_id="prep-"+_sha(_bytes(list(identity)))
        row=tx.read(METADATA_TABLE,{"pk":PREPARATION_PK,"sk":"PREPARATION#"+prep_id})
        if (not isinstance(row,dict) or set(row)!={"pk","sk","intent","state","receipts"}
                or row["state"] not in {"preparing","live","retired"} or not isinstance(row["receipts"],dict)):
            _reject("preparation_not_ready")
        intent=self._validate_intent(row["intent"])
        if (intent["articleId"],intent["locale"],intent["revisionId"],intent["recordPurpose"])!=(article,locale,revision,purpose): _reject()
        expected={s["key"]:s for s in intent["objects"]}
        if set(row["receipts"])!={_sha(k.encode()) for k in expected}: _reject("preparation_not_ready")
        variants=[];bundle_pointer=None
        for object_id,receipt in row["receipts"].items():
            self._receipt_for(expected,receipt)
            if object_id!=_sha(receipt["key"].encode()): _reject()
            if receipt["key"]==bundle_key(article,locale,revision):
                bundle_pointer={k:receipt[k] for k in ("key","versionId","sha256")}
            else:
                asset,filename=receipt["key"].split("/")[-2:]
                variants.append({"assetId":asset,"variantId":filename.rsplit(".",1)[0],"objectKey":receipt["key"],
                    **{k:receipt[k] for k in ("versionId","contentType","bytes","sha256")}})
        bundle=self._json(self.delivery_bucket,bundle_pointer,MAX_OBJECT_BYTES)
        from content_hub_v2_projection import FIELDS,build_public_bundle
        try: fields={k:bundle["variables"]["journalArticle"][k] for k in FIELDS}
        except (TypeError,KeyError): _reject("publication_integrity_failed")
        live={"fields":fields,"revisionId":revision,"bundle":bundle}
        build_public_bundle(article,locale,live)
        media=build_delivery_manifest(article,locale,revision,sorted(variants,key=lambda v:(v["assetId"],v["variantId"])))
        cache[identity]=(row,live,media)
        return cache[identity]

    @staticmethod
    def _receipt_for(expected,receipt):
        AwsPreparationStore._receipt(SimpleNamespace(expected=expected),receipt)

    @staticmethod
    def _asset_ids(value):
        if not isinstance(value,list) or len(value)>21 or any(not isinstance(v,str) for v in value) or len(value)!=len(set(value)): _reject()
        for asset in value: safe_id(asset)
        return set(value)

    def _assets(self,tx,row,locale,new_ids,purpose,now):
        state=row["locales"][locale]
        working=self._asset_ids(state.get("workingAssetIds",[]))
        published=self._asset_ids(state.get("publishedAssetIds",[]))
        result={}
        for asset in sorted(working|published|new_ids):
            key={"pk":PARTITION_PREFIX+f"ASSETS#{row['articleId']}#{locale}","sk":"ASSET#"+asset}
            value=tx.read(METADATA_TABLE,key)
            identity={**THN_CURRENT_USER_SCOPE,"articleId":row["articleId"],"locale":locale,"assetId":asset,"recordPurpose":purpose}
            count=int(asset in working)+int(asset in published)
            if (not isinstance(value,dict) or any(value.get(k)!=v for k,v in identity.items())
                    or value.get("status")!="ready" or value.get("deliveryState")!="private"
                    or type(value.get("referenceCount")) is not int or value["referenceCount"]!=count):
                _reject("asset_not_available")
            result[asset]=value
            next_count=int(asset in working)+int(asset in new_ids)
            if next_count!=count:
                tx.put(METADATA_TABLE,{**value,"referenceCount":next_count,"referencesUpdatedAtEpoch":now})
        return result

    def _check_working_package(self,row,locale,revision,live,assets,prep,purpose,now):
        state=row["locales"][locale];pointer=state.get("packagePointer")
        key=PRIVATE_PREFIX+f"immutable-revisions/{row['articleId']}/{locale}/{revision}/package.json"
        if not isinstance(pointer,dict) or pointer.get("key")!=key: _reject()
        package=normalize_package({**self._json(self.private_bucket,pointer,MAX_PACKAGE_BYTES),"seriesId":row["seriesId"]})
        if set(referenced_assets(package))!=self._asset_ids(state.get("workingAssetIds",[])): _reject("invalid_asset_references")
        fields=live["fields"]
        if state.get("path") and fields["path"]!=state["path"]: _reject("publication_path_changed")
        if fields["publishedAt"]!=(state.get("firstPublishedAt") or fields["updatedAt"]): _reject("publication_date_changed")
        if datetime.fromisoformat(fields["updatedAt"].replace("Z","+00:00")).timestamp()>now: _reject()
        rebuilt=build_locale_projection(row["articleId"],locale,revision,package,assets,path=fields["path"],
            first_published_at=fields["publishedAt"],updated_at=fields["updatedAt"])
        if rebuilt!=live: _reject("publication_integrity_failed")
        source=_source_variants(row["articleId"],locale,revision,package,assets,purpose)
        expected=[v["destination"] for v in source]
        actual=[v for v in prep["intent"]["objects"] if v["contentType"]!="application/json"]
        if expected!=actual: _reject("publication_integrity_failed")

    @staticmethod
    def _reservation(tx,article,locale,path,purpose):
        key={"pk":PARTITION_PREFIX+"PATHS#"+locale,"sk":"PATH#"+path}
        wanted={**key,**THN_CURRENT_USER_SCOPE,"recordType":"THN_CONTENT_HUB_V2_PATH_RESERVATION",
                "articleId":article,"locale":locale,"path":path,"recordPurpose":purpose}
        old=tx.read(METADATA_TABLE,key)
        if old is not None and old!=wanted: _reject("publication_path_conflict")
        if old is None: tx.put(METADATA_TABLE,wanted)

    def _commit(self,tx,initial_guards,purpose):
        fresh=self._guards(purpose)
        # A guard factory cannot silently switch the captured actor or registry.
        initial=deepcopy(initial_guards);current=deepcopy(fresh)
        started=initial[2]["ConditionCheck"]["ExpressionAttributeValues"].pop(":now")
        completed=current[2]["ConditionCheck"]["ExpressionAttributeValues"].pop(":now")
        if initial!=current or int(completed["N"])<int(started["N"]): _reject("publication_authority_changed")
        items=[*fresh,*tx.items()]
        if len(items)>90 or len(_bytes(items))>3_500_000: _reject("publication_limit")
        try: self.ddb.transact_write_items(TransactItems=items)
        except Exception as error:
            if getattr(error,"response",{}).get("Error",{}).get("Code")=="TransactionCanceledException": raise EditorConflict() from None
            raise

    def finalize_publication_transaction(self,*,article_id,locale,revision_id,expected_token,operation_id):
        safe_id(revision_id)
        return self._finalize("publish",article_id,locale,revision_id,expected_token,operation_id)

    def finalize_unpublish_transaction(self,*,article_id,locale,expected_token,operation_id):
        return self._finalize("unpublish",article_id,locale,"",expected_token,operation_id)

    def allocate_publication(self,*,article_id,locale,revision_id,expected_token):
        """Reserve a hidden auto-URL before immutable preparation can collide.

        This separate, private-only fenced transaction cannot publish anything.
        A losing allocation may be retried before any delivery object is made.
        Unpublish never releases reservations, and retries preserve timestamps.
        """
        safe_id(article_id);safe_locale(locale);safe_id(revision_id);safe_id(expected_token)
        guards=self._guards();authority=unmarshal_item(guards[2]["ConditionCheck"]["ExpressionAttributeValues"])
        purpose,now=authority[":purpose"],authority[":now"]
        tx=_Transaction(self.ddb)
        row=tx.read(METADATA_TABLE,{"pk":ARTICLE_PK,"sk":"ARTICLE#"+article_id})
        if (not isinstance(row,dict) or row.get("articleId")!=article_id or row.get("recordPurpose")!=purpose
                or any(row.get(k)!=v for k,v in THN_CURRENT_USER_SCOPE.items())
                or not isinstance(row.get("locales"),dict) or locale not in row["locales"]): _reject()
        state=row["locales"][locale]
        if row.get("concurrencyToken")!=expected_token or state.get("workingRevisionId")!=revision_id: raise EditorConflict()
        key={"pk":OPERATION_PK,"sk":f"ALLOCATION#{article_id}#{locale}#{revision_id}"}
        old=tx.read(METADATA_TABLE,key)
        identity={**key,**THN_CURRENT_USER_SCOPE,"recordType":"THN_CONTENT_HUB_V2_PUBLICATION_ALLOCATION",
            "recordPurpose":purpose,"articleId":article_id,"locale":locale,"revisionId":revision_id}
        if old is not None:
            if set(old)!=set(identity)|{"selection"} or any(old.get(k)!=v for k,v in identity.items()): _reject()
            selection=old["selection"]
            if not isinstance(selection,dict) or set(selection)!={"path","firstPublishedAt","updatedAt"}: _reject()
            from content_hub_v2_projection import _timestamp
            if (_timestamp(selection["updatedAt"])<_timestamp(selection["firstPublishedAt"])
                    or not isinstance(selection["path"],str) or re.fullmatch(r"/the-journal/[a-z0-9-]+/[a-z0-9-]+",selection["path"]) is None): _reject()
            self._reservation(tx,article_id,locale,selection["path"],purpose)
            self._commit(tx,guards,purpose)
            return deepcopy(selection)
        pointer=state.get("packagePointer")
        if not isinstance(pointer,dict) or pointer.get("key")!=PRIVATE_PREFIX+f"immutable-revisions/{article_id}/{locale}/{revision_id}/package.json": _reject()
        package=normalize_package({**self._json(self.private_bucket,pointer,MAX_PACKAGE_BYTES),"seriesId":row["seriesId"]})
        selected=state.get("path")
        if not selected:
            for ordinal in range(1,101):
                candidate=article_path(locale,row["seriesId"],package["title"],ordinal)
                path_key={"pk":PARTITION_PREFIX+"PATHS#"+locale,"sk":"PATH#"+candidate}
                # Occupied alternatives do not participate in this transaction;
                # only the chosen candidate is re-read and conditionally reserved.
                response=self.ddb.get_item(TableName=METADATA_TABLE,Key=marshal_item(path_key),ConsistentRead=True)
                occupant=unmarshal_item(response["Item"]) if response.get("Item") else None
                if occupant is None or (occupant.get("articleId")==article_id and occupant.get("recordPurpose")==purpose):
                    selected=candidate;break
            if not selected: _reject("publication_path_capacity")
        self._reservation(tx,article_id,locale,selected,purpose)
        timestamp=datetime.fromtimestamp(now,timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
        selection={"path":selected,"firstPublishedAt":state.get("firstPublishedAt") or timestamp,"updatedAt":timestamp}
        # Reuse an earlier immutable revision's dates when it is already prepared
        # or was published and retired; never overwrite that revision's bundle.
        prep_id="prep-"+_sha(_bytes([article_id,locale,revision_id]))
        prepared=tx.read(METADATA_TABLE,{"pk":PREPARATION_PK,"sk":"PREPARATION#"+prep_id})
        if prepared is not None:
            _,live,_=self._prepared(tx,article_id,locale,revision_id,purpose,{})
            if live["fields"]["path"]!=selected: _reject("publication_path_conflict")
            selection={"path":selected,"firstPublishedAt":live["fields"]["publishedAt"],"updatedAt":live["fields"]["updatedAt"]}
        tx.put(METADATA_TABLE,{**identity,"selection":selection})
        self._commit(tx,guards,purpose)
        return selection

    def _finalize(self,operation,article,locale,revision,expected_token,operation_id):
        safe_id(article);safe_locale(locale);safe_id(expected_token)
        if not isinstance(operation_id,str) or re.fullmatch(r"[a-f0-9]{32}",operation_id) is None: _reject("invalid_operation_id")
        guards=self._guards();authority=unmarshal_item(guards[2]["ConditionCheck"]["ExpressionAttributeValues"])
        purpose,now=authority[":purpose"],authority[":now"]
        registry=unmarshal_item(guards[0]["ConditionCheck"]["ExpressionAttributeValues"])
        epoch=registry[":writerEpoch"]
        actor_hash=_sha((PARTITION_PREFIX+authority[":subject"]).encode())
        digest=_sha(_bytes({**THN_CURRENT_USER_SCOPE,"operation":operation,"articleId":article,"locale":locale,
            "revisionId":revision,"expectedToken":expected_token,"recordPurpose":purpose,"actorHash":actor_hash}))
        tx=_Transaction(self.ddb)
        op_key={"pk":OPERATION_PK,"sk":"OPERATION#"+operation_id}
        prior=tx.read(METADATA_TABLE,op_key)
        if prior is not None:
            if (set(prior)!={"pk","sk","recordType","requestDigest","recordPurpose","result"}
                    or prior.get("recordType")!="THN_CONTENT_HUB_V2_PUBLICATION_RECEIPT"
                    or prior.get("requestDigest")!=digest or prior.get("recordPurpose")!=purpose): _reject("publication_replay_conflict")
            result=prior["result"]
            if (not isinstance(result,dict) or set(result)!={"articleId","locale","state","concurrencyToken"}
                    or result["articleId"]!=article or result["locale"]!=locale
                    or result["state"]!={"publish":"published","unpublish":"unpublished"}[operation]): _reject("publication_replay_conflict")
            safe_id(result["concurrencyToken"])
            self._commit(tx,guards,purpose)
            return deepcopy(result)
        row=tx.read(METADATA_TABLE,{"pk":ARTICLE_PK,"sk":"ARTICLE#"+article})
        if (not isinstance(row,dict) or row.get("articleId")!=article or row.get("recordPurpose")!=purpose
                or any(row.get(k)!=v for k,v in THN_CURRENT_USER_SCOPE.items())
                or not isinstance(row.get("locales"),dict) or set(row["locales"])-{"en","es"} or locale not in row["locales"]): _reject()
        if row.get("concurrencyToken")!=expected_token: raise EditorConflict()
        state=row["locales"][locale]
        if operation=="publish" and state.get("workingRevisionId")!=revision: raise EditorConflict()
        before={};before_media={};cache={}
        for language,value in row["locales"].items():
            if value.get("publishedRevisionId"):
                old,live,media=self._prepared(tx,article,language,safe_id(value["publishedRevisionId"]),purpose,cache)
                if old["state"]!="live": _reject("projection_reconciliation_required")
                before[language]=live;before_media[language]=media
                if (value.get("path")!=live["fields"]["path"] or value.get("firstPublishedAt")!=live["fields"]["publishedAt"]
                        or self._asset_ids(value.get("publishedAssetIds",[]))!={v["assetId"] for v in media["variants"]}): _reject()
        after=deepcopy(before);after_media=deepcopy(before_media)
        if operation=="publish":
            prepared,live,media=self._prepared(tx,article,locale,revision,purpose,cache)
            new_ids={v["assetId"] for v in media["variants"]}
            assets=self._assets(tx,row,locale,new_ids,purpose,now)
            self._check_working_package(row,locale,revision,live,assets,prepared,purpose,now)
            self._reservation(tx,article,locale,live["fields"]["path"],purpose)
            after[locale]=live;after_media[locale]=media
        else:
            new_ids=set();self._assets(tx,row,locale,new_ids,purpose,now)
            after.pop(locale,None);after_media.pop(locale,None)
        delta=build_projection_delta(article,before,before_media,after,after_media)
        # Unchanged sibling pointers are part of the expected projection too.
        # Fencing only changed rows could silently retain a missing stale locale.
        if before:
            expected_rows=[build_article_index_item(article,before),*build_category_items(article,before),
                *before_media.values(),*[build_slug_pointer(article,language,value) for language,value in before.items()]]
            for expected in expected_rows:
                tx.expect(self.public_table,{k:expected[k] for k in ("pk","sk")},expected)
        for change in delta["changes"]:
            target=change["before"] or change["after"];key={k:target[k] for k in ("pk","sk")}
            tx.expect(self.public_table,key,change["before"])
            if change["after"] is None: tx.delete(self.public_table,key)
            else: tx.put(self.public_table,change["after"])
        changed=bool(delta["changes"])
        token=_sha(_bytes([digest,operation_id,"committed"]))[:32] if changed else expected_token
        result={"articleId":article,"locale":locale,"state":"published" if locale in after else "unpublished","concurrencyToken":token}
        if changed:
            updated=deepcopy(row);updated["concurrencyToken"]=token
            updated["updatedAt"]=datetime.fromtimestamp(now,timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
            new_state=updated["locales"][locale];new_state["publishedAssetIds"]=sorted(new_ids)
            if operation=="publish":
                new_state.update(publishedRevisionId=revision,firstPublishedAt=live["fields"]["publishedAt"],path=live["fields"]["path"])
                updated["seriesLocked"]=True
            else: new_state.pop("publishedRevisionId",None)
            if len(_bytes(updated))>65536: _reject("metadata_too_large")
            tx.put(METADATA_TABLE,updated)
            previous=before.get(locale,{}).get("revisionId")
            if previous and (operation=="unpublish" or previous!=revision):
                old=cache[article,locale,previous][0];tx.put(METADATA_TABLE,{**old,"state":"retired"})
            if operation=="publish": tx.put(METADATA_TABLE,{**prepared,"state":"live"})
            manifest=update_manifest(tx,article,delta,epoch,operation_id)
            outbox={"pk":f"OUTBOX#test#thehairnarrative.com#thehairnarrative-com-journal#PUBLICATION",
                "sk":"OPERATION#"+operation_id,"recordType":"THN_CONTENT_HUB_V2_INVALIDATION_OUTBOX","schemaVersion":1,
                "environment":"test","domain":"thehairnarrative.com","hubId":"thehairnarrative-com-journal",
                "source":"publication","operation":operation,"articleId":article,"locale":locale,
                "manifestId":manifest["manifestId"],"projectionDigest":manifest["projectionDigest"],"writerEpoch":epoch,
                "status":"pending","paths":delta["invalidationPaths"],"pathCount":len(delta["invalidationPaths"]),"attemptCount":0}
            if tx.read(METADATA_TABLE,{k:outbox[k] for k in ("pk","sk")}) is not None: raise EditorConflict()
            tx.put(METADATA_TABLE,outbox)
        elif before:
            check_live_membership(tx,article,delta["beforePointers"],epoch)
        audit={"pk":f"AUDIT#test#thehairnarrative.com#thehairnarrative-com-journal#{article}","sk":"PUBLICATION#"+operation_id,
            "operation":operation,"articleId":article,"locale":locale,"actorHash":actor_hash,"writerEpoch":epoch,
            "timestampEpoch":now,"decision":"committed" if changed else "unchanged"}
        if tx.read(AUDIT_TABLE,{k:audit[k] for k in ("pk","sk")}) is not None: raise EditorConflict()
        tx.put(AUDIT_TABLE,audit)
        tx.put(METADATA_TABLE,{**op_key,"recordType":"THN_CONTENT_HUB_V2_PUBLICATION_RECEIPT",
            "requestDigest":digest,"recordPurpose":purpose,"result":result})
        self._commit(tx,guards,purpose)
        return result
