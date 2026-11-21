"""One narrowly defined v1 compatibility patch; this is not a general release mode."""
from __future__ import annotations

import ast
import io
import tokenize


class PatchRejected(ValueError):
    """Sanitized guard failure; never include source/provider values."""


def require(condition, message='v1_publication_date_patch_rejected'):
    if not condition:
        raise PatchRejected(message)


SUPPORT_FILES = frozenset({
    '.github/workflows/deploy-production.yml',
    'tools/classify_production_promotion.py',
    'tools/v1_publication_date_patch.py',
    'tools/release_v1_publication_date.py',
    'tests/test_classify_production_promotion.py',
    'tests/test_v1_publication_date_patch.py',
    'tests/test_v1_publication_date_release.py',
    'tests/test_content_hub_handler.py',
    'README.md',
    'changelog/2026-11-20-preserve-article-publication-date.md',
})


def _dump(node):
    return ast.dump(node, include_attributes=False)


def _date_value(mapping):
    require(isinstance(mapping, ast.Dict))
    positions=[i for i,key in enumerate(mapping.keys) if isinstance(key,ast.Constant) and key.value=='publishedAt']
    require(len(positions)==1)
    index=positions[0]
    require(_dump(mapping.values[index])==_dump(ast.Name(id='now',ctx=ast.Load())))
    mapping.values[index]=ast.Name(id='published_at',ctx=ast.Load())


def validate_publish_date_change(before: str, after: str) -> bool:
    """Reconstruct exactly the four reviewed AST edits; compare the entire module."""
    require(isinstance(before,str) and isinstance(after,str),'v1_existing_python_source_required')
    try:
        require(all(tokenize.detect_encoding(io.BytesIO(source.encode('utf-8')).readline)[0]=='utf-8' for source in (before,after)),'v1_source_encoding_changed')
        expected=ast.parse(before)
        candidate=ast.parse(after)
    except (SyntaxError,TypeError,ValueError,UnicodeError):
        raise PatchRejected('v1_source_not_python') from None
    functions=[n for n in expected.body if isinstance(n,ast.FunctionDef) and n.name=='_publish_article']
    require(len(functions)==1)
    publisher=functions[0]
    require(not any(isinstance(n,ast.Name) and n.id=='published_at' for n in ast.walk(publisher)), 'v1_patch_already_applied')
    now_ast=ast.parse('now = _now_iso()').body[0]
    now_positions=[i for i,node in enumerate(publisher.body) if _dump(node)==_dump(now_ast)]
    require(len(now_positions)==1)
    calls=[n for n in ast.walk(publisher) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='_article_bundle']
    require(len(calls)==1 and len(calls[0].args)>9 and not calls[0].keywords)
    require(isinstance(calls[0].args[8],ast.Constant) and calls[0].args[8].value=='published')
    require(_dump(calls[0].args[9])==_dump(ast.Name(id='now',ctx=ast.Load())))
    calls[0].args[9]=ast.Name(id='published_at',ctx=ast.Load())
    updates=[n for n in ast.walk(publisher) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='store' and n.func.attr=='update_metadata']
    require(len(updates)==1 and len(updates[0].args)==3)
    _date_value(updates[0].args[2])
    returns=[n for n in ast.walk(publisher) if isinstance(n,ast.Return)]
    require(len(returns)==1)
    _date_value(returns[0].value)
    publisher.body.insert(now_positions[0]+1,ast.parse('published_at = article.get("publishedAt") or now').body[0])
    require(_dump(expected)==_dump(candidate),'v1_source_semantics_outside_exact_date_patch')
    return True


def validate_source_patch(before: dict[str,str|None], after: dict[str,str|None]) -> bool:
    changed={name for name in set(before)|set(after) if before.get(name)!=after.get(name)}
    require('lambda_function.py' in changed, 'v1_runtime_patch_missing')
    require(changed <= SUPPORT_FILES|{'lambda_function.py'}, 'v1_unrelated_source_changed')
    require(all(isinstance(after.get(name),str) for name in changed), 'v1_source_deletion_rejected')
    validate_publish_date_change(before.get('lambda_function.py'),after.get('lambda_function.py'))
    return True
