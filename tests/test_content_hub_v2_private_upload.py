"""Test the private media journey through real use cases and storage boundaries."""
import base64
from copy import deepcopy
import hashlib
import unittest
from types import SimpleNamespace

from content_hub_v2_authorization import THN_CURRENT_USER_SCOPE
from content_hub_v2_editor_model import EditorValidationError
from content_hub_v2_editor_service import EditorConflict

try:
    from content_hub_v2_private_upload import PrivateUpload, validate_upload
except ImportError:
    PrivateUpload = validate_upload = None


SOURCE = b"\x89PNG\r\n\x1a\nfixture"  # Processor, not the gateway, fully decodes images.


class MediaStore:
    """Storage/processor boundary fixture; no use-case behavior is mocked."""
    def __init__(self):
        self.auth = SimpleNamespace(account_purpose="client-owner", writer_epoch=7)
        self.row = {**THN_CURRENT_USER_SCOPE, "articleId": "article-1", "recordPurpose": "client-owner",
                    "concurrencyToken": "token-1", "locales": {"en": {"workingRevisionId": "revision-1"}}}
        self.transactions, self.assets, self.invocations = {}, {}, []
        self.time, self.after_invoke = 1000, lambda: None

    def now_epoch(self):
        return self.time

    def load_upload(self, transaction_id):
        return deepcopy(self.transactions.get(transaction_id))

    def begin_upload(self, row, transaction, authorize):
        authorize()
        self.transactions.setdefault(transaction["transactionId"], deepcopy(transaction))

    def process_upload(self, transaction, image_base64):
        self.invocations.append(transaction["transactionId"])
        row = self.transactions[transaction["transactionId"]]
        row.update(status="consumed", processingState="ready", deliveryState="private", referenceCount=0,
                   sourceWidth=320, sourceHeight=200,
                   variants=[{"variantId": "w" + str(w), "width": 320, "height": 200, "bytes": len(SOURCE),
                              "sha256": hashlib.sha256(SOURCE).hexdigest(), "contentType": "image/png", "versionId": "v1"}
                             for w in (480, 768, 1200, 1600)])
        self.after_invoke()
        return {"ok": True}

    def finish_upload(self, row, transaction, asset, authorize):
        authorize()
        if row["concurrencyToken"] != self.row["concurrencyToken"]:
            raise EditorConflict()
        if transaction["writerEpoch"] != self.auth.writer_epoch:
            raise EditorValidationError("writer_changed")
        self.assets.setdefault(asset["assetId"], deepcopy(asset))


class PrivateUploadTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(PrivateUpload, "Private upload coordinator must be implemented")
        self.store = MediaStore()
        self.allowed = True
        self.data = {"articleId": "article-1", "locale": "en", "concurrencyToken": "token-1",
                     "imageBase64": base64.b64encode(SOURCE).decode(), "contentType": "image/png", "alt": "A quiet hairstyle"}

    def authorize(self):
        if not self.allowed:
            raise PermissionError("revoked")

    def upload(self):
        return PrivateUpload(self.store)(deepcopy(self.store.row), "en", self.data, self.authorize)

    def test_upload_is_private_scope_bound_versioned_and_retry_is_idempotent(self):
        first = self.upload()
        again = self.upload()
        self.assertEqual(first, again)
        self.assertEqual(len(self.store.invocations), 1)
        self.assertEqual(len(self.store.assets), 1)
        tx = next(iter(self.store.transactions.values()))
        self.assertEqual(tx["actorPurpose"], "client-owner")
        self.assertEqual(tx["revisionId"], "revision-1")
        self.assertEqual(tx["expiresAtEpoch"], 1900)
        self.assertEqual(tx["contentSha256"], hashlib.sha256(SOURCE).hexdigest())
        self.assertEqual(first["asset"]["status"], "ready")
        for private in ("variants", "versionId", "actorPurpose", "writerEpoch", "privateKey", "imageBase64"):
            self.assertNotIn(private, str(first))

    def test_qa_uses_actual_account_purpose_not_writer_mode(self):
        self.store.auth.account_purpose = self.store.row["recordPurpose"] = "qa"
        self.upload()
        self.assertEqual(next(iter(self.store.transactions.values()))["actorPurpose"], "qa")

    def test_revocation_during_processing_never_exposes_an_asset(self):
        self.store.after_invoke = lambda: setattr(self, "allowed", False)
        with self.assertRaises(PermissionError):
            self.upload()
        self.assertEqual(self.store.assets, {})

    def test_epoch_change_and_concurrent_edit_prevent_final_commit(self):
        for callback, error in ((lambda: setattr(self.store.auth, "writer_epoch", 8), EditorValidationError),
                                (lambda: self.store.row.update(concurrencyToken="token-2"), EditorConflict)):
            with self.subTest(error=error):
                self.store = MediaStore()
                self.store.after_invoke = callback
                with self.assertRaises(error):
                    self.upload()
                self.assertEqual(self.store.assets, {})

    def test_consumed_transaction_cannot_be_rebound_to_another_revision(self):
        self.upload()
        tx = next(iter(self.store.transactions.values()))
        tx["revisionId"] = "other-revision"
        with self.assertRaises(EditorValidationError):
            self.upload()
        self.assertEqual(len(self.store.invocations), 1)

    def test_corrupt_or_unversioned_processor_result_never_reaches_asset_state(self):
        def corrupt():
            next(iter(self.store.transactions.values()))["variants"][0].pop("versionId")
        self.store.after_invoke = corrupt
        with self.assertRaises(EditorValidationError):
            self.upload()
        self.assertEqual(self.store.assets, {})

    def test_transaction_identity_cannot_change_between_processing_and_return(self):
        for field, value in (("assetId", "other"), ("recordType", "foreign"), ("transactionId", "other")):
            with self.subTest(field=field):
                self.store = MediaStore()
                self.store.after_invoke = lambda: next(iter(self.store.transactions.values())).update({field: value})
                with self.assertRaises(EditorValidationError):
                    self.upload()
                self.assertEqual(self.store.assets, {})

    def test_alt_text_cannot_be_blank_on_upload(self):
        self.data["alt"] = "  "
        with self.assertRaises(EditorValidationError):
            self.upload()
        self.assertEqual(self.store.transactions, {})

    def test_payload_type_base64_magic_and_size_fail_before_storage(self):
        for changes in ({"contentType": "image/svg+xml"}, {"imageBase64": "?"},
                        {"contentType": "image/jpeg"}, {"alt": "a" * 241},
                        {"imageBase64": base64.b64encode(b"a" * 4194305).decode()}):
            with self.subTest(fields=list(changes)):
                with self.assertRaises(EditorValidationError):
                    PrivateUpload(self.store)(self.store.row, "en", {**self.data, **changes}, self.authorize)
                self.assertEqual(self.store.transactions, {})

    def test_expiry_and_attempt_exhaustion_fail_closed(self):
        self.upload()
        tx = next(iter(self.store.transactions.values()))
        tx.update(status="pending", attemptCount=3)
        with self.assertRaises(EditorValidationError):
            self.upload()
        tx.update(attemptCount=0, expiresAtEpoch=1000)
        with self.assertRaises(EditorValidationError):
            self.upload()
