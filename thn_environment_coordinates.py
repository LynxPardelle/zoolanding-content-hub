"""Private code-owned resource-coordinate projection; no browser selectors."""
from thn_environment_profile import PROFILE

_ANCHORS = (
    ('zoolanding-content-hub-test','zoolanding-content-hub-prod'),
    ('zoolanding-auth-admin-test','zoolanding-auth-admin-prod'),
    ('zoolanding-image-upload-test','zoolanding-image-upload-production'),
    ('zlp-thn-private-upload-test-','zlp-thn-private-upload-production-'),
    ('zlp-thn-ch-test-','zlp-thn-ch-production-'),
    ('thn-journal-test-v2','thn-journal-production-v2'),
    ('admin-test.thehairnarrative.com','admin.thehairnarrative.com'),
    ('test.zoolandingpage.com.mx','thehairnarrative.com'),
    ('endefiz7dkk635k6di6k','ltnafwb6videyraictgp'),
    ('#test#','#production#'),
    ('private/test/','private/production/'),
    ('content-hubs/test/','content-hubs/production/'),
    (':test',':production'),
)

def coordinate(value):
    """Resolve only literals/trusted immutable coordinates used by private code.

    Profile selection is sealed at import. This helper is not an input contract
    and is never applied to proposed browser scope or descriptor policy fields.
    """
    if not isinstance(value,str): raise ValueError('THN resource coordinate invalid')
    if PROFILE['environment']=='test': return value
    if value=='test': return 'production'
    for old,new in _ANCHORS: value=value.replace(old,new)
    if '-test-' in value or '#test#' in value or 'private/test/' in value or 'content-hubs/test/' in value or 'admin-test.' in value:
        raise ValueError('THN production coordinate is unrecognized')
    return value
