from local_settings import *
from datetime import timedelta

APPLICATION_ROOT = '/user'
DEBUG = True
OAUTH2_PROVIDER_ERROR_URI = "/api/oauth2/errors"


HOST_NAME = 'http://api.bloodpac-data.org'
SHIBBOLETH_HEADER = 'persistent_id'
SSO_URL = 'https://itrusteauth.nih.gov/affwebservices/public/saml2sso?SPID=https://bionimbus-pdc.opensciencedatacloud.org/shibboleth&RelayState='
SINGLE_LOGOUT = 'https://itrusteauth.nih.gov/siteminderagent/smlogout.asp?mode=nih&AppReturnUrl=https://bionimbus-pdc.opensciencedatacloud.org/storage/login'

LOGOUT = "https://bionimbus-pdc.opensciencedatacloud.org/auth/logout/?next=/Shibboleth.sso/Logout%3Freturn%3Dhttps%3A%2F%2Fbionimbus-pdc.opensciencedatacloud.org/api"
BIONIMBUS_ACCOUNT_ID = 655886864976

# stale session time
SESSION_TIMEOUT = timedelta(seconds=1800)
# max session lifetime
SESSION_LIFETIME = timedelta(seconds=28800)
SESSION_COOKIE_NAME = "fence_session"
