"""Private preparation of immutable THN publication objects.

This service has no SDK or Lambda entrypoint. Its injected store must atomically
reserve each intent, conditionally create immutable objects and persist exact
versioned receipts. No live pointer or delivery manifest is written here.
"""
from copy import deepcopy
import hashlib
import json
import re
from typing import Protocol

from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE
from content_hub_v2_editor_model import EditorValidationError, normalize_package, referenced_assets, safe_id, safe_locale
from content_hub_v2_projection import (
    ROOT, VARIANTS, EXTENSIONS, build_locale_projection, build_public_bundle,
    build_delivery_manifest, bundle_key,
)

SOURCE_ROOT = "private/test/thehairnarrative.com/journal-owner/thehairnarrative-com/thehairnarrative-com-journal/articles/"
MAX_OBJECT_BYTES = 4_194_304


class PreparationStore(Protocol):
    def begin_preparation(self, intent: dict) -> dict:
        """Create once, or return identical existing intent with original age."""
        ...
    def read_private_variant(self, pointer: dict):
        """Read only the exact trusted private-store object version."""
        ...
    def put_prepared_object(self, spec: dict, body: bytes) -> dict:
        """Create-only in private delivery storage; retry must verify digest."""
        ...
    def record_prepared_object(self, preparation_id: str, receipt: dict) -> None:
        """Persist one exact expected object/version; never mark it live."""
        ...


def _reject(code="invalid_prepared_objects"):
    raise EditorValidationError(code)


def _bytes(value):
    return json.dumps(value,ensure_ascii=False,allow_nan=False,sort_keys=True,separators=(",",":")).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _version(value):
    if (not isinstance(value,str) or value == "null"
            or re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,1024}",value) is None):
        _reject()
    return value


def _source_variants(article_id,locale,revision_id,package,assets,purpose):
    selected=[]
    for asset_id in sorted(referenced_assets(package)):
        asset=assets.get(asset_id)
        identity={**THN_CURRENT_USER_SCOPE,"articleId":article_id,"locale":locale,"assetId":asset_id}
        if (not isinstance(asset,dict) or any(asset.get(k)!=v for k,v in identity.items())
                or asset.get("recordPurpose")!=purpose or asset.get("status")!="ready"
                or asset.get("deliveryState")!="private" or type(asset.get("referenceCount")) is not int
                or not 1<=asset["referenceCount"]<=2):
            _reject("asset_not_available")
        variants=asset.get("variants")
        if (not isinstance(variants,list) or len(variants)!=4
                or [v.get("variantId") for v in variants if isinstance(v,dict)]!=list(VARIANTS)):
            _reject()
        source_revisions=set()
        content_types=set()
        for value in variants:
            extension=EXTENSIONS.get(value.get("contentType"))
            key=value.get("key")
            if (not extension or not isinstance(key,str) or type(value.get("bytes")) is not int
                    or not 0<value["bytes"]<=MAX_OBJECT_BYTES or not isinstance(value.get("sha256"),str)
                    or re.fullmatch(r"[a-f0-9]{64}",value["sha256"]) is None):
                _reject()
            _version(value.get("versionId"))
            match=re.fullmatch(re.escape(SOURCE_ROOT+f"{article_id}/{locale}/revisions/")
                +r"([A-Za-z0-9][A-Za-z0-9_-]{0,79})"
                +re.escape(f"/assets/{asset_id}/{value['variantId']}.{extension}"),key)
            if not match:
                _reject()
            source_revisions.add(match[1])
            content_types.add(value["contentType"])
            source={k:value[k] for k in ("key","versionId","contentType","bytes","sha256")}
            destination={"key":f"{ROOT}/{locale}/{article_id}/{revision_id}/media/{asset_id}/{value['variantId']}.{extension}",
                         **{k:value[k] for k in ("contentType","bytes","sha256")}}
            selected.append({"assetId":asset_id,"variantId":value["variantId"],"source":source,"destination":destination})
        if len(source_revisions)!=1 or len(content_types)!=1:
            _reject()
    return selected


def _persist(store,preparation_id,spec,body,authorize):
    authorize()
    receipt=store.put_prepared_object(deepcopy(spec),body)
    if (not isinstance(receipt,dict) or set(receipt)!=set(spec)|{"versionId"}
            or type(receipt.get("bytes")) is not int
            or any(receipt.get(k)!=v for k,v in spec.items())):
        _reject("invalid_prepared_receipt")
    _version(receipt["versionId"])
    # A crash before the receipt leaves an exact-key intent, not a live object.
    # The future orphan adapter must resolve only this intent's key and digest.
    authorize()
    store.record_prepared_object(preparation_id,deepcopy(receipt))
    return receipt


def prepare_immutable_objects(*,article_id,locale,revision_id,package,assets,path,
                              first_published_at,updated_at,purpose,now_epoch,
                              store:PreparationStore,authorize):
    """Return private receipts and a manifest candidate, never public state."""
    safe_id(article_id);safe_locale(locale);safe_id(revision_id)
    if (purpose not in {"qa","client-owner"} or type(now_epoch) is not int or now_epoch<0
            or not callable(authorize) or not isinstance(assets,dict)):
        _reject()
    normalized=normalize_package(package)
    live=build_locale_projection(article_id,locale,revision_id,normalized,assets,
                                path=path,first_published_at=first_published_at,updated_at=updated_at)
    variants=_source_variants(article_id,locale,revision_id,normalized,assets,purpose)
    body=_bytes(build_public_bundle(article_id,locale,live))
    if len(body)>MAX_OBJECT_BYTES:
        _reject("public_bundle_too_large")
    bundle_spec={"key":bundle_key(article_id,locale,revision_id),"bytes":len(body),
                 "sha256":_sha(body),"contentType":"application/json"}
    material={**THN_CURRENT_USER_SCOPE,"articleId":article_id,"locale":locale,
              "revisionId":revision_id,"recordPurpose":purpose,
              "objects":[v["destination"] for v in variants]+[bundle_spec]}
    intent={**material,"preparationId":"prep-"+_sha(_bytes([article_id,locale,revision_id])),
            "recordType":"THN_CONTENT_HUB_V2_PREPARATION","schemaVersion":1,
            "intentDigest":_sha(_bytes(material)),"candidateAtEpoch":now_epoch,"state":"preparing"}
    authorize()
    existing=store.begin_preparation(deepcopy(intent))
    if (not isinstance(existing,dict) or set(existing)!=set(intent)
            or type(existing.get("schemaVersion")) is not int
            or any(existing.get(k)!=v for k,v in intent.items() if k!="candidateAtEpoch")
            or type(existing.get("candidateAtEpoch")) is not int
            or not 0<=existing["candidateAtEpoch"]<=now_epoch):
        _reject("preparation_conflict")
    receipts=[]; copied=[]
    for variant in variants:
        authorize()
        source=variant["source"]
        stream=store.read_private_variant(deepcopy(source))
        try:
            data=stream.read(MAX_OBJECT_BYTES+1)
        finally:
            stream.close()
        if not isinstance(data,bytes) or len(data)!=source["bytes"] or _sha(data)!=source["sha256"]:
            _reject("image_integrity_failed")
        receipt=_persist(store,intent["preparationId"],variant["destination"],data,authorize)
        receipts.append(receipt)
        copied.append({"assetId":variant["assetId"],"variantId":variant["variantId"],
                       "objectKey":receipt["key"],**{k:receipt[k] for k in ("versionId","contentType","bytes","sha256")}})
    pointer=_persist(store,intent["preparationId"],bundle_spec,body,authorize)
    receipts.append(pointer)
    authorize()
    return {"preparation":{**existing,"state":"prepared"},"objects":deepcopy(receipts),
            "bundlePointer":{k:pointer[k] for k in ("key","versionId","sha256")},
            "deliveryManifest":build_delivery_manifest(article_id,locale,revision_id,copied)}
