# Production S3 SDK model preflight

Protected Content Hub state review `36787606263` stopped before package upload
or change-set creation with `production_import_live_bucket_changed`. The live
retained bucket remains versioned, encrypted with AES256, blocks SSE-C, and has
all four public-access blocks enabled. The source template agrees.

The review installed `boto3==1.39.13`. Its S3 response model omits the
`BlockedEncryptionTypes` field from `GetBucketEncryption`, so the guard read an
incomplete rule and reported a false mismatch. Replaying the same read with
`boto3==1.43.105` returns the field and matches the live bucket. The import
workflow already pins that newer version.

Runtime and release requirements now pin the same newer SDK. A local contract
test fails with the old model and passes only when the installed SDK exposes
`BlockedEncryptionTypes`. No guard rule was relaxed and the failed review did
not change the production stack.

In a clean local virtual environment using the updated pins, 552 repository
tests (5 skipped), 134 standalone release tests, `pip check`, and dependency
audits for both requirement files passed. The live S3 read with the pinned SDK
returns the complete encryption rule and matches the imported template.
