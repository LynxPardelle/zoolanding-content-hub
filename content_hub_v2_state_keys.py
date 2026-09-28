"""Fixed THN private coordinates; no clients, handlers or authoring methods."""

from thn_environment_coordinates import coordinate
from thn_environment_profile import PROFILE
PRIVATE_PREFIX = coordinate("private/test/thehairnarrative.com/thehairnarrative-com-journal/")
PARTITION_PREFIX = coordinate("THN#test#thehairnarrative.com#journal-owner#thehairnarrative-com#thehairnarrative-com-journal#")
ARTICLE_PK = PARTITION_PREFIX + "ARTICLES"
METADATA_TABLE = coordinate("zoolanding-content-hub-test-ThnContentHubV2Metadata")
AUDIT_TABLE = coordinate("zoolanding-content-hub-test-ThnContentHubV2Audit")
