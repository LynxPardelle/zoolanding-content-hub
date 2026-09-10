"""Executable fixed-editor contract; all media/identities are synthetic."""
from copy import deepcopy
import unittest

import content_hub_v2_editor_model as model


def package(**changes):
    value = {"title": "Forma y movimiento", "summary": "Una observación del cabello.",
             "seriesId": "form-movement", "tags": ["borrador"],
             "cover": {"assetId": "asset-cover", "alt": "Recogido", "focalX": 50, "focalY": 50},
             "delta": {"ops": [{"insert": "Primera observación.\nOtra idea.\n"}]}}
    value.update(changes)
    return value


class EditorModelTests(unittest.TestCase):
    def test_fixed_package_round_trip_and_partial_draft(self):
        self.assertEqual(model.normalize_package(package()), package())
        blank = model.normalize_package({})
        self.assertEqual(blank["title"], "")
        self.assertEqual(blank["delta"], {"ops": [{"insert": "\n"}]})
        self.assertTrue(model.publication_errors(blank, {}))

    def test_unknown_fields_and_limits_fail_closed(self):
        for change in ({"html": "<script>x</script>"}, {"url": "custom"},
                       {"title": "a" * 161}, {"summary": "a" * 481},
                       {"seriesId": "other"}, {"tags": ["x"] * 13},
                       {"cover": {"assetId": "../x", "alt": "a", "focalX": 0, "focalY": 0}},
                       {"cover": {"assetId": "a", "alt": "a", "focalX": True, "focalY": 50}}):
            with self.subTest(fields=list(change)), self.assertRaises(model.EditorValidationError):
                model.normalize_package({**package(), **change})

    def test_delta_compiles_real_paragraphs_headings_lists_and_quotes(self):
        delta = {"ops": [{"insert": "Heading"}, {"insert": "\n", "attributes": {"header": 2}},
                         {"insert": "Hello", "attributes": {"bold": True}}, {"insert": " world\n"},
                         {"insert": "One"}, {"insert": "\n", "attributes": {"list": "ordered"}},
                         {"insert": "Two"}, {"insert": "\n", "attributes": {"list": "ordered"}},
                         {"insert": "Quote"}, {"insert": "\n", "attributes": {"blockquote": True}}]}
        html = model.compile_delta(delta, {})
        self.assertEqual(html, "<h2>Heading</h2><p><strong>Hello</strong> world</p><ol><li>One</li><li>Two</li></ol><blockquote>Quote</blockquote>")

    def test_escapes_text_and_link_attributes(self):
        delta = {"ops": [{"insert": '<script>&"', "attributes": {"link": "https://example.test/?a=1&b=2"}}, {"insert": "\n"}]}
        result = model.compile_delta(delta, {})
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)
        self.assertIn("&amp;b=2", result)

    def test_rejects_active_links_and_arbitrary_embeds(self):
        for url in ("javascript:alert(1)", "data:text/html,x", "//evil.test", "/\\evil.test", "https://user:pass@example.test", "https:\\evil.test", "https://example.test/\n"):
            with self.subTest(url=url), self.assertRaises(model.EditorValidationError):
                model.compile_delta({"ops": [{"insert": "link", "attributes": {"link": url}}, {"insert": "\n"}]}, {})
        for op in ({"insert": {"video": "x"}}, {"insert": "x", "attributes": {"style": "color:red"}},
                   {"retain": 5}, {"insert": "x", "attributes": {"header": 1}},
                   {"insert": {"image": "https://example.test/x.jpg"}}):
            with self.subTest(op=op), self.assertRaises(model.EditorValidationError):
                model.compile_delta({"ops": [op, {"insert": "\n"}]}, {})

    def test_inline_media_uses_only_resolved_generated_routes(self):
        delta = {"ops": [{"insert": {"image": "asset-1"}}, {"insert": "\n"}]}
        with self.assertRaises(model.EditorValidationError):
            model.compile_delta(delta, {})
        value = model.compile_delta(delta, {"asset-1": {"src": "/features/content-hub-v2/public-media/a/en/r/asset-1/768", "alt": '<image>'}})
        self.assertIn('<figure><img src="/features/content-hub-v2/public-media/', value)
        self.assertIn('alt="&lt;image&gt;"', value)
        self.assertNotIn("undefined", value)

    def test_delta_and_inline_count_are_bounded(self):
        for ops in ([{"insert": "x"}] * 1001, [{"insert": "x" * 524289}],
                    [{"insert": {"image": f"a-{i}"}} for i in range(21)]):
            with self.assertRaises(model.EditorValidationError):
                model.normalize_package(package(delta={"ops": ops}))

    def test_publish_requires_ready_referenced_media_and_nonempty_body(self):
        assets = {"asset-cover": {"status": "ready"}}
        self.assertEqual(model.publication_errors(package(), assets), [])
        self.assertIn("cover_not_ready", model.publication_errors(package(), {}))
        self.assertIn("body_required", model.publication_errors(package(delta={"ops": [{"insert": "\n"}]}), assets))
        self.assertIn("title_required", model.publication_errors(package(title="  "), assets))

    def test_urls_are_automatic_localized_and_stable_after_first_publication(self):
        self.assertEqual(model.slugify("  Observación & MÉTODO!  "), "observacion-metodo")
        self.assertEqual(model.article_path("es", "form-movement", "Observación & MÉTODO!"), "/the-journal/forma-y-movimiento/observacion-metodo")
        self.assertEqual(model.article_path("en", "bridal-forms", "Bridal", ordinal=2), "/the-journal/bridal-forms/bridal-2")
        self.assertEqual(model.locale_state({"workingRevisionId": "r2", "publishedRevisionId": "r1"}), "updates-pending")
        self.assertEqual(model.locale_state({"workingRevisionId": "r1", "firstPublishedAt": "2026-01-01"}), "unpublished")
        self.assertEqual(model.locale_state({"workingRevisionId": "r1", "publishedRevisionId": "r1"}), "published")
        self.assertEqual(model.locale_state({}), "draft")

    def test_normalization_never_mutates_input(self):
        original = package()
        saved = deepcopy(original)
        model.normalize_package(original)
        self.assertEqual(original, saved)


if __name__ == "__main__":
    unittest.main()
