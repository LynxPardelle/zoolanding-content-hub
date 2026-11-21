"""Credential-free selection of an exact reviewed TEST -> main merge.

The sole deployable v1 exception preserves first-publication dates. There is no
general legacy fallback, hash-only bypass, or V2 deployment in this workflow.
"""
import json
import os
import re
import sys
import pathlib
import subprocess

ROOT=pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from tools.v1_publication_date_patch import PatchRejected, validate_source_patch

COORDINATES = ("sourceSha", "sourceTree", "targetBaseSha", "mergeTree")
FIELDS = {"schemaVersion", "mode", *COORDINATES}
class PromotionSelectionError(ValueError):
    pass

def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise PromotionSelectionError("production_selection_invalid")
        result[key] = value
    return result

def _git(value):
    return isinstance(value,str) and bool(re.fullmatch(r"[a-f0-9]{40}",value)) and value != "0"*40

def classify_selection(raw, *, sourceSha, sourceTree, targetBaseSha, mergeTree, v1_documents=None):
    context = dict(sourceSha=sourceSha,sourceTree=sourceTree,targetBaseSha=targetBaseSha,mergeTree=mergeTree)
    if not all(_git(value) for value in context.values()):
        raise PromotionSelectionError("production_context_invalid")
    try:
        if not isinstance(raw,str) or not raw or len(raw.encode('utf-8'))>4096: raise ValueError()
        value = json.loads(raw,object_pairs_hook=_object)
        if not isinstance(value,dict) or set(value)!=FIELDS or type(value['schemaVersion']) is not int or value['schemaVersion']!=1 or value['mode'] not in {'thn-source-only','v1-preserve-published-at'} or not all(_git(value[key]) for key in COORDINATES): raise ValueError()
    except (ValueError,UnicodeError,RecursionError):
        raise PromotionSelectionError("production_selection_invalid") from None
    if any(value[key]!=context[key] for key in COORDINATES):
        raise PromotionSelectionError("production_selection_stale")
    if value['mode']=='v1-preserve-published-at':
        try:
            if not isinstance(v1_documents,tuple) or len(v1_documents)!=2:raise PatchRejected()
            validate_source_patch(*v1_documents)
        except (PatchRejected,TypeError):
            raise PromotionSelectionError('production_v1_date_patch_invalid') from None
    return value['mode']

def git_patch_documents(target_base,merge_tree):
    if not _git(target_base) or not _git(merge_tree):raise PromotionSelectionError('production_context_invalid')
    def git(*args,missing=False):
        result=subprocess.run(['git',*args],cwd=ROOT,capture_output=True)
        if result.returncode:
            if missing:return None
            raise PromotionSelectionError('production_source_unavailable')
        return result.stdout.decode('utf-8')
    names=git('diff','--name-only','--no-renames','-z',target_base,merge_tree).split('\0')
    before={};after={}
    for name in filter(None,names):
        before[name]=git('show',target_base+':'+name,missing=True)
        after[name]=git('show',merge_tree+':'+name,missing=True)
    return before,after

def main(argv=None):
    try:
        if sys.argv[1:] if argv is None else argv: raise PromotionSelectionError("production_arguments_invalid")
        raw=os.environ.get("PRODUCTION_PROMOTION_SELECTION_JSON")
        context={key:os.environ.get("PROMOTED_"+re.sub(r"([a-z])([A-Z])",r"\1_\2",key).upper()) for key in COORDINATES}
        try:requested=json.loads(raw or '{}').get('mode')
        except (ValueError,AttributeError):requested=None
        documents=git_patch_documents(context['targetBaseSha'],context['mergeTree']) if requested=='v1-preserve-published-at' else None
        mode=classify_selection(raw, **context,v1_documents=documents)
    except PromotionSelectionError as error:
        print(str(error),file=sys.stderr)
        return 2
    print(mode)
    return 0
if __name__=='__main__': raise SystemExit(main())
