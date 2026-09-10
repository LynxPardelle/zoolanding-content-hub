"""Pure, closed THN public projections. No SDK, credentials, or private-store I/O."""
from copy import deepcopy
from datetime import datetime
import re
from content_hub_v2_editor_model import (
    EditorValidationError, SERIES, compile_delta, normalize_package,
    publication_errors, referenced_assets, safe_id, safe_locale,
)

DOMAIN = "thehairnarrative.com"
HUB_ID = "thehairnarrative-com-journal"
ROOT = f"content-hubs/test/{HUB_ID}/published/{DOMAIN}"
FIELDS = frozenset(("title","summary","path","categorySlug","publishedAt","updatedAt",
    "canonicalPath","robots","imageSrc","imageAlt"))
VARIANTS = ("w480","w768","w1200","w1600")
EXTENSIONS = {"image/jpeg":"jpg","image/png":"png","image/webp":"webp"}


def _reject():
    raise EditorValidationError("invalid_public_projection")


def _timestamp(value):
    if not isinstance(value,str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",value):
        _reject()
    try:
        return datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError:
        _reject()


def bundle_key(article_id, locale, revision_id):
    return f"{ROOT}/{safe_locale(locale)}/{safe_id(article_id)}/{safe_id(revision_id)}/bundle.json"


def media_url(article_id, locale, revision_id, asset_id, variant_id="w1200"):
    if variant_id not in VARIANTS:
        _reject()
    return f"/features/content-hub-v2/public-media/{safe_id(article_id)}/{safe_locale(locale)}/{safe_id(revision_id)}/{safe_id(asset_id)}/{variant_id}"


def _live(article_id, locale, live):
    safe_id(article_id); safe_locale(locale)
    if not isinstance(live,dict) or set(live)!={"fields","revisionId","bundle"}:
        _reject()
    safe_id(live["revisionId"])
    fields=live["fields"]
    if not isinstance(fields,dict) or set(fields)!=FIELDS or any(not isinstance(v,str) for v in fields.values()):
        _reject()
    if (_timestamp(fields["updatedAt"]) < _timestamp(fields["publishedAt"])
            or fields["robots"]!="index,follow" or fields["canonicalPath"]!=fields["path"]
            or not re.fullmatch(r"/the-journal/[a-z0-9-]+/[a-z0-9-]+",fields["path"])
            or fields["path"].split("/")[2]!=fields["categorySlug"]):
        _reject()
    if fields["categorySlug"] not in {series[locale][1] for series in SERIES.values()}:
        _reject()
    bundle=live["bundle"]
    if (not isinstance(bundle,dict) or set(bundle)!={"articleId","locale","path","status","variables","seo"}
            or bundle.get("articleId")!=article_id or bundle.get("locale")!=locale
            or bundle.get("path")!=fields["path"] or bundle.get("status")!="published"):
        _reject()
    variables=bundle["variables"]
    if not isinstance(variables,dict) or set(variables)!={"articleContent","journalArticle"}:
        _reject()
    content,display=variables["articleContent"],variables["journalArticle"]
    if not isinstance(content,dict) or set(content)!={"html"} or not isinstance(content["html"],str):
        _reject()
    if not isinstance(display,dict) or set(display)!=FIELDS|{"seriesTitle","coverFocalX","coverFocalY"}:
        _reject()
    if any(display[k]!=v for k,v in fields.items()):
        _reject()
    if any(type(display[k]) not in (int,float) or not 0<=display[k]<=100 for k in ("coverFocalX","coverFocalY")):
        _reject()
    if display["seriesTitle"] not in {series[locale][0] for series in SERIES.values() if series[locale][1]==fields["categorySlug"]}:
        _reject()
    if bundle["seo"]!={"title":fields["title"],"description":fields["summary"],"canonical":fields["path"],"robots":"index,follow"}:
        _reject()
    return fields


def build_locale_projection(article_id, locale, revision_id, package, assets, *,
                            path, first_published_at, updated_at):
    safe_id(article_id); safe_locale(locale); safe_id(revision_id)
    normalized=normalize_package(package)
    if publication_errors(normalized,assets):
        _reject()
    category=SERIES[normalized["seriesId"]][locale][1]
    if not isinstance(path,str) or not re.fullmatch(re.escape(f"/the-journal/{category}/")+r"[a-z0-9]+(?:-[a-z0-9]+)*",path):
        _reject()
    if _timestamp(updated_at) < _timestamp(first_published_at):
        _reject()
    cover=normalized["cover"]
    media={asset_id:{"src":media_url(article_id,locale,revision_id,asset_id),
                     "alt":assets[asset_id].get("alt","")} for asset_id in referenced_assets(normalized)}
    fields={"title":normalized["title"],"summary":normalized["summary"],"path":path,"categorySlug":category,
        "publishedAt":first_published_at,"updatedAt":updated_at,"canonicalPath":path,"robots":"index,follow",
        "imageSrc":media_url(article_id,locale,revision_id,cover["assetId"]),"imageAlt":cover["alt"]}
    # Runtime Read overlays variables from an immutable bundle. Private Delta,
    # tags, ownership and pointers never enter it; focal coordinates are display data.
    bundle={"articleId":article_id,"locale":locale,"path":path,"status":"published",
        "variables":{"articleContent":{"html":compile_delta(normalized["delta"],media)},
                     "journalArticle":{**fields,"seriesTitle":SERIES[normalized["seriesId"]][locale][0],
                         "coverFocalX":cover["focalX"],"coverFocalY":cover["focalY"]}},
        "seo":{"title":fields["title"],"description":fields["summary"],
               "canonical":path,"robots":"index,follow"}}
    return {"fields":fields,"revisionId":revision_id,"bundle":bundle}


def select_primary_locale(live_locales):
    if not isinstance(live_locales,dict) or set(live_locales)-{"en","es"}:
        _reject()
    return next((locale for locale in ("en","es") if locale in live_locales),None)


def build_article_index_item(article_id, live_locales):
    safe_id(article_id)
    selected=select_primary_locale(live_locales)
    if selected is None:
        return None
    localized={locale:deepcopy(_live(article_id,locale,live)) for locale,live in live_locales.items()}
    return {"pk":f"HUB#{HUB_ID}","sk":f"ARTICLE#{article_id}","articleId":article_id,
        "hubId":HUB_ID,"itemFamily":"ARTICLE",
        "locale":selected,"status":"published","visibility":"public",**localized[selected],
        "localizations":localized,
        "publishedBundleKey":bundle_key(article_id,selected,live_locales[selected]["revisionId"])}


def build_slug_pointer(article_id, locale, live):
    fields=_live(article_id,locale,live)
    return {"pk":f"SLUG#test#{DOMAIN}#{locale}","sk":"PATH#"+fields["path"],
        "articleId":article_id,"hubId":HUB_ID,"itemFamily":"SLUG","revisionId":live["revisionId"],
        "locale":locale,"path":fields["path"],"status":"published","visibility":"public",
        "publishedBundleKey":bundle_key(article_id,locale,live["revisionId"])}


def build_category_items(article_id, live_locales):
    select_primary_locale(live_locales)
    return [{"pk":f"HUB#{HUB_ID}","sk":f"CATEGORY#{locale}#{_live(article_id,locale,live)['categorySlug']}#ARTICLE#{article_id}",
        "articleId":article_id,"hubId":HUB_ID,"itemFamily":"CATEGORY_INDEX","revisionId":live["revisionId"],
        "locale":locale,"status":"published","visibility":"public",**deepcopy(live["fields"])}
        for locale,live in live_locales.items()]


def build_public_bundle(article_id, locale, live):
    _live(article_id,locale,live)
    return deepcopy(live["bundle"])


def build_delivery_manifest(article_id, locale, revision_id, copied_variants):
    safe_id(article_id);safe_locale(locale);safe_id(revision_id)
    if not isinstance(copied_variants,list) or not 4<=len(copied_variants)<=84:
        _reject()
    seen=set(); variants=[]
    for value in copied_variants:
        if not isinstance(value,dict) or set(value)!={"assetId","variantId","objectKey","versionId","contentType","bytes","sha256"}:
            _reject()
        asset_id=safe_id(value["assetId"]); variant=value["variantId"]
        extension=EXTENSIONS.get(value["contentType"])
        if (variant not in VARIANTS or not extension or (asset_id,variant) in seen
                or value["objectKey"]!=f"{ROOT}/{locale}/{article_id}/{revision_id}/media/{asset_id}/{variant}.{extension}"
                or not isinstance(value["versionId"],str) or value["versionId"]=="null"
                or not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,1024}",value["versionId"])
                or type(value["bytes"]) is not int or not 0<value["bytes"]<=4*1024*1024
                or not isinstance(value["sha256"],str) or not re.fullmatch(r"[a-f0-9]{64}",value["sha256"])):
            _reject()
        seen.add((asset_id,variant));variants.append(dict(value))
    if any({v for a,v in seen if a==asset_id}!=set(VARIANTS) for asset_id,_ in seen):
        _reject()
    return {"pk":f"LIVE_MEDIA#test#{DOMAIN}#{HUB_ID}#{article_id}#{locale}#{revision_id}","sk":"MANIFEST#V1",
        "recordType":"THN_CONTENT_HUB_V2_LIVE_MEDIA_MANIFEST","schemaVersion":1,"environment":"test",
        "domain":DOMAIN,"hubId":HUB_ID,"articleId":article_id,"locale":locale,"revisionId":revision_id,
        "status":"published","visibility":"public","deliveryState":"live","variants":variants}
