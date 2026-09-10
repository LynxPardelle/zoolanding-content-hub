"""Pure, bounded changes for one THN article's public pointers.

Input snapshots must come from validated immutable packages, not browser data.
This module does not commit anything. The publisher must include these changes,
private publication/reference state, manifest checkpoint and outbox in its ONE
guarded final transaction. Applying these changes individually is unsupported.
"""
from copy import deepcopy
from html.parser import HTMLParser

from content_hub_v2_editor_model import EditorValidationError, SERIES, safe_id
from content_hub_v2_projection import (
    build_article_index_item, build_category_items, build_delivery_manifest,
    build_public_bundle, build_slug_pointer, media_url, select_primary_locale,
)
from content_hub_v2_projection_manifest import GLOBAL_INVALIDATION_PATHS, validate_projection_pointer


def _reject():
    raise EditorValidationError("invalid_projection_transition")


class _ImageSources(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.sources=[]

    def handle_starttag(self,tag,attrs):
        if tag=="img":
            sources=[value for name,value in attrs if name=="src"]
            if len(sources)!=1: _reject()
            self.sources.append(sources[0])


def _snapshot(article_id,live_locales,media_manifests):
    selected=select_primary_locale(live_locales)
    if not isinstance(media_manifests,dict) or set(media_manifests)!=set(live_locales):
        _reject()
    rows={};pointers=[]

    def add(row,kind,locale,revision,paths,**extra):
        key=(row["pk"],row["sk"])
        if key in rows: _reject()
        rows[key]=deepcopy(row)
        pointers.append(validate_projection_pointer({"pointerType":kind,"pk":key[0],"sk":key[1],
            "articleId":article_id,"locale":locale,"revisionId":revision,"invalidationPaths":paths,**extra}))

    if selected is None: return rows,pointers
    add(build_article_index_item(article_id,live_locales),"article",selected,live_locales[selected]["revisionId"],[])
    categories={row["locale"]:row for row in build_category_items(article_id,live_locales)}
    for locale in sorted(live_locales):
        live=live_locales[locale]
        bundle=build_public_bundle(article_id,locale,live)
        revision=live["revisionId"]
        manifest=media_manifests[locale]
        if not isinstance(manifest,dict) or "variants" not in manifest:
            _reject()
        if manifest!=build_delivery_manifest(article_id,locale,revision,manifest["variants"]):
            _reject()
        allowed={media_url(article_id,locale,revision,v["assetId"],v["variantId"]):v["assetId"]
                 for v in manifest["variants"]}
        parser=_ImageSources()
        parser.feed(bundle["variables"]["articleContent"]["html"])
        parser.close()
        sources=[live["fields"]["imageSrc"],*parser.sources]
        if any(src not in allowed for src in sources) or {allowed[src] for src in sources}!={v["assetId"] for v in manifest["variants"]}:
            _reject()
        path=live["fields"]["path"]; category=live["fields"]["categorySlug"]
        add(build_slug_pointer(article_id,locale,live),"locale-path",locale,revision,[path],path=path)
        add(categories[locale],"category-index",locale,revision,["/the-journal/"+category],categorySlug=category)
        add(manifest,"public-media",locale,revision,sorted(allowed))
    return rows,pointers


def build_projection_delta(article_id,before_locales,before_media,after_locales,after_media):
    """Return exact compare-and-replace rows and withdraw/cache inventories.

    There are at most seven live rows (one index plus three per language), and
    at most fourteen distinct target keys in a transition. Each returned change
    contains the full expected prior row: the final store must condition its
    write on that expectation, or on absence for a first publication.
    """
    safe_id(article_id)
    before,before_pointers=_snapshot(article_id,before_locales,before_media)
    after,after_pointers=_snapshot(article_id,after_locales,after_media)
    series_ids=set()
    for locales in (before_locales,after_locales):
        for locale,live in locales.items():
            series_ids.update(key for key,series in SERIES.items() if series[locale][1]==live["fields"]["categorySlug"])
    if len(series_ids)>1: _reject()
    for locale in set(before_locales)&set(after_locales):
        old,new=before_locales[locale],after_locales[locale]
        if (any(old["fields"][field]!=new["fields"][field] for field in ("path","publishedAt","categorySlug"))
                or new["fields"]["updatedAt"]<old["fields"]["updatedAt"]):
            _reject()
        if old["revisionId"]==new["revisionId"] and (old!=new or before_media[locale]!=after_media[locale]):
            _reject()
    changes=[{"before":before.get(key),"after":after.get(key)} for key in sorted(set(before)|set(after))
             if before.get(key)!=after.get(key)]
    paths=[]
    if changes:
        paths=list(GLOBAL_INVALIDATION_PATHS)
        for pointer in [*before_pointers,*after_pointers]: paths.extend(pointer["invalidationPaths"])
        paths=list(dict.fromkeys(paths))
    return deepcopy({"changes":changes,"beforePointers":before_pointers,"afterPointers":after_pointers,
                     "invalidationPaths":paths})
