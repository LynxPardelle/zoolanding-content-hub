"""Bounded linked-manifest maintenance inside the publisher's final transaction.

One closed withdrawal page per article. Private bidirectional links let removal
touch only the article and immediate neighbors, never a scan or unbounded walk.
"""
from content_hub_v2_editor_model import EditorValidationError,safe_id
from content_hub_v2_state_keys import METADATA_TABLE
from content_hub_v2_preparation import _bytes,_sha
from content_hub_v2_projection_manifest import (MANIFEST_PK,MANIFEST_SK,seal_projection_manifest,
    seal_projection_page,validate_projection_manifest,validate_projection_page)


def _reject():
    raise EditorValidationError("projection_reconciliation_required")


def _link(tx,article,manifest_id):
    safe_id(article)
    row=tx.read(METADATA_TABLE,{"pk":MANIFEST_PK,"sk":"LINK#"+article})
    if (not isinstance(row,dict) or set(row)!={"pk","sk","recordType","manifestId","pageId","previousPageId","nextPageId"}
            or row["recordType"]!="THN_CONTENT_HUB_V2_PROJECTION_LINK" or row["manifestId"]!=manifest_id or row["pageId"]!=article): _reject()
    for field in ("previousPageId","nextPageId"):
        if row[field]: safe_id(row[field])
        if row[field]==article: _reject()
    return row


def check_live_membership(tx,article,pointers,epoch):
    """Fence a no-op against a still-live checkpoint, not only private metadata."""
    header=validate_projection_manifest(tx.read(METADATA_TABLE,{"pk":MANIFEST_PK,"sk":MANIFEST_SK}))
    if header["state"]!="live" or header["publicationWriterEpoch"]!=epoch: _reject()
    page=validate_projection_page(tx.read(METADATA_TABLE,{"pk":MANIFEST_PK,"sk":"PAGE#"+article}))
    link=_link(tx,article,header["manifestId"])
    if (page["manifestId"]!=header["manifestId"] or page["pageId"]!=article
            or page["livePointers"]!=pointers or page["nextPageId"]!=link["nextPageId"]
            or (link["previousPageId"]=="")!=(header["headPageId"]==article)): _reject()


def update_manifest(tx,article,delta,epoch,operation_id):
    header=tx.read(METADATA_TABLE,{"pk":MANIFEST_PK,"sk":MANIFEST_SK})
    before,after=delta["beforePointers"],delta["afterPointers"]
    if header is None:
        if before: _reject()
        manifest_id="m-"+_sha(operation_id.encode())[:40]
        header=seal_projection_manifest(manifest_id=manifest_id,projection_digest=_sha(b"empty"),
            publication_writer_epoch=epoch,head_page_id="",page_count=0,pointer_count=0)
    else:
        header=validate_projection_manifest(header)
        if header["state"]!="live" or header["publicationWriterEpoch"]!=epoch: _reject()
        manifest_id=header["manifestId"]
    page_key={"pk":MANIFEST_PK,"sk":"PAGE#"+article}
    link_key={"pk":MANIFEST_PK,"sk":"LINK#"+article}
    page=tx.read(METADATA_TABLE,page_key)
    head=header["headPageId"]
    page_count=header["remainingPageCount"]
    pointer_count=header["livePointerCount"]-len(before)+len(after)
    if before:
        page=validate_projection_page(page)
        link=_link(tx,article,manifest_id)
        if (page["manifestId"]!=manifest_id or page["pageId"]!=article or page["livePointers"]!=before
                or link["nextPageId"]!=page["nextPageId"] or (link["previousPageId"]=="")!=(head==article)): _reject()
        if after:
            tx.put(METADATA_TABLE,seal_projection_page(manifest_id=manifest_id,page_id=article,
                next_page_id=page["nextPageId"],live_pointers=after))
        else:
            previous,following=link["previousPageId"],link["nextPageId"]
            if previous:
                previous_link=_link(tx,previous,manifest_id)
                previous_page=validate_projection_page(tx.read(METADATA_TABLE,{"pk":MANIFEST_PK,"sk":"PAGE#"+previous}))
                if previous_link["nextPageId"]!=article or previous_page["nextPageId"]!=article or previous_page["manifestId"]!=manifest_id: _reject()
                tx.put(METADATA_TABLE,{**previous_link,"nextPageId":following})
                tx.put(METADATA_TABLE,seal_projection_page(manifest_id=manifest_id,page_id=previous,
                    next_page_id=following,live_pointers=previous_page["livePointers"]))
            else: head=following
            if following:
                next_link=_link(tx,following,manifest_id)
                if next_link["previousPageId"]!=article: _reject()
                tx.put(METADATA_TABLE,{**next_link,"previousPageId":previous})
            tx.delete(METADATA_TABLE,page_key);tx.delete(METADATA_TABLE,link_key);page_count-=1
    else:
        if not after or page is not None or tx.read(METADATA_TABLE,link_key) is not None: _reject()
        if head:
            head_link=_link(tx,head,manifest_id)
            head_page=validate_projection_page(tx.read(METADATA_TABLE,{"pk":MANIFEST_PK,"sk":"PAGE#"+head}))
            if (head_link["previousPageId"] or head_page["manifestId"]!=manifest_id or head_page["pageId"]!=head
                    or head_page["nextPageId"]!=head_link["nextPageId"]): _reject()
            tx.put(METADATA_TABLE,{**head_link,"previousPageId":article})
        tx.put(METADATA_TABLE,{**link_key,"recordType":"THN_CONTENT_HUB_V2_PROJECTION_LINK",
            "manifestId":manifest_id,"pageId":article,"previousPageId":"","nextPageId":head})
        tx.put(METADATA_TABLE,seal_projection_page(manifest_id=manifest_id,page_id=article,next_page_id=head,live_pointers=after))
        head=article;page_count+=1
    result=seal_projection_manifest(manifest_id=manifest_id,projection_digest=_sha(_bytes({"previous":header["projectionDigest"],
        "operationId":operation_id,"articleId":article,"pointers":after})),publication_writer_epoch=epoch,
        head_page_id=head,page_count=page_count,pointer_count=pointer_count)
    tx.put(METADATA_TABLE,result)
    return result
