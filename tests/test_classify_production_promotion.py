import json
import unittest
from tools.classify_production_promotion import classify_selection, PromotionSelectionError
from test_v1_publication_date_patch import BEFORE, AFTER

CONTEXT = dict(sourceSha="a"*40,sourceTree="b"*40,targetBaseSha="c"*40,mergeTree="d"*40)
class ProductionPromotionSelectionTests(unittest.TestCase):
    def selection(self, **updates):
        return json.dumps({"schemaVersion":1,"mode":"thn-source-only",**CONTEXT,**updates})
    def test_exact_source_only_selection(self):
        self.assertEqual(classify_selection(self.selection(), **CONTEXT), "thn-source-only")
    def test_missing_selection_never_deploys(self):
        for raw in (None,"","{}"):
            with self.assertRaises(PromotionSelectionError): classify_selection(raw, **CONTEXT)
    def test_every_coordinate_is_pinned(self):
        for key in CONTEXT:
            value=json.loads(self.selection());value[key]="e"*40
            with self.assertRaises(PromotionSelectionError): classify_selection(json.dumps(value), **CONTEXT)
    def test_duplicates_unknown_fields_and_legacy_are_closed(self):
        valid=self.selection()
        for raw in (valid[:-1]+',"sourceSha":"'+"a"*40+'"}', valid[:-1]+',"other":1}', valid.replace("thn-source-only","legacy")):
            with self.assertRaises(PromotionSelectionError): classify_selection(raw, **CONTEXT)
    def test_context_and_schema_are_strict(self):
        for bad in ("0"*40,"A"*40,"short"):
            context=dict(CONTEXT);context['sourceSha']=bad
            with self.assertRaises(PromotionSelectionError): classify_selection(self.selection(), **context)
        value=json.loads(self.selection());value['schemaVersion']=True
        with self.assertRaises(PromotionSelectionError): classify_selection(json.dumps(value), **CONTEXT)

    def test_compatible_v1_mode_requires_exact_semantics_and_source_scope(self):
        selection=self.selection(mode="v1-preserve-published-at")
        documents=({'lambda_function.py':BEFORE},{'lambda_function.py':AFTER})
        self.assertEqual(classify_selection(selection, **CONTEXT, v1_documents=documents), "v1-preserve-published-at")
        for bad in (None, ({'lambda_function.py':BEFORE},{'lambda_function.py':AFTER,'template.yaml':'infra drift'}), ({'lambda_function.py':BEFORE},{'lambda_function.py':AFTER.replace('"updatedAt": now','"updatedAt": published_at')})):
            with self.subTest(documents=bad), self.assertRaises(PromotionSelectionError):
                classify_selection(selection, **CONTEXT, v1_documents=bad)

    def test_v1_mode_keeps_pinned_context_and_no_legacy_fallback(self):
        value=json.loads(self.selection(mode="v1-preserve-published-at"));value['targetBaseSha']='e'*40
        with self.assertRaises(PromotionSelectionError):
            classify_selection(json.dumps(value),**CONTEXT,v1_documents=({'lambda_function.py':BEFORE},{'lambda_function.py':AFTER}))
