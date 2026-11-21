import unittest

from tools.v1_publication_date_patch import PatchRejected, validate_source_patch, validate_publish_date_change


BEFORE = '''
def untouched():
    return "approved"

def _publish_article(payload, binding, session, profile, hub):
    article = store.get_metadata("article")
    now = _now_iso()
    bundle = _article_bundle(article, revision, package, profile, hub, domain, locale, path,
                             "published", now, title, description)
    store.update_metadata(pk, sk, {"publishedAt": now, "updatedAt": now})
    return {"publishedAt": now, "revisionId": revision_id}
'''
AFTER = BEFORE.replace('    now = _now_iso()\n', '    now = _now_iso()\n    published_at = article.get("publishedAt") or now\n').replace('"published", now,', '"published", published_at,').replace('"publishedAt": now', '"publishedAt": published_at')


class V1PublicationDatePatchGuardTests(unittest.TestCase):
    def test_only_exact_first_publication_preservation_semantics_are_allowed(self):
        self.assertTrue(validate_publish_date_change(BEFORE, AFTER))
        self.assertTrue(validate_publish_date_change(BEFORE, AFTER.replace('def untouched():', '# unchanged semantics\ndef untouched():')))

    def test_arbitrary_publisher_logic_and_payload_dates_are_rejected(self):
        for candidate in (
            AFTER.replace('article.get("publishedAt") or now', 'payload.get("publishedAt") or now'),
            AFTER.replace('article.get("publishedAt") or now', 'now'),
            AFTER.replace('"updatedAt": now', '"updatedAt": published_at'),
            AFTER.replace('"revisionId": revision_id', '"revisionId": "different"'),
            AFTER.replace('bundle = _article_bundle', 'raise RuntimeError("skip publish")\n    bundle = _article_bundle'),
            AFTER.replace('"published", published_at,', '"published", now,'),
            AFTER.replace('"publishedAt": published_at, "updatedAt"', '"publishedAt": now, "updatedAt"'),
        ):
            with self.subTest(candidate=candidate), self.assertRaises(PatchRejected):
                validate_publish_date_change(BEFORE, candidate)

    def test_changes_outside_publish_and_already_patched_base_are_rejected(self):
        for before, after in ((BEFORE, AFTER.replace('return "approved"', 'return "bypassed"')), (BEFORE, AFTER+'\ndef new_handler(): pass\n'), (BEFORE,'# coding: latin-1\n'+AFTER), (AFTER, AFTER), (BEFORE, BEFORE)):
            with self.subTest(before=before, after=after), self.assertRaises(PatchRejected):
                validate_publish_date_change(before, after)

    def test_runtime_infrastructure_dependencies_and_deletions_are_rejected(self):
        before={'lambda_function.py':BEFORE}
        self.assertTrue(validate_source_patch(before, {'lambda_function.py':AFTER}))
        for filename in ('template.yaml','samconfig.toml','requirements.txt','publisher_lambda.py','content_hub_v2_authoring_handler.py','.github/workflows/deploy-thn-production.yml'):
            with self.subTest(filename=filename), self.assertRaises(PatchRejected):
                validate_source_patch(before, {'lambda_function.py':AFTER,filename:'changed'})
        with self.assertRaises(PatchRejected):
            validate_source_patch(before,{})
        with self.assertRaises(PatchRejected):
            validate_source_patch({}, {'lambda_function.py':AFTER})

    def test_declared_release_support_files_do_not_expand_runtime_scope(self):
        before={'lambda_function.py':BEFORE,'tools/classify_production_promotion.py':'old guard'}
        after={'lambda_function.py':AFTER,'tools/classify_production_promotion.py':'reviewed guard', 'tests/test_v1_publication_date_patch.py':'offline tests'}
        self.assertTrue(validate_source_patch(before,after))


if __name__=='__main__':
    unittest.main()
