from collections import OrderedDict
from datetime import timedelta


APPLICATION_ROOT = '/user'
DEBUG = True
OAUTH2_PROVIDER_ERROR_URI = "/api/oauth2/errors"

BIONIMBUS_ACCOUNT_ID = 655886864976

ACCESS_TOKEN_LIFETIME = timedelta(seconds=600)
ACCESS_TOKEN_COOKIE_NAME = "access_token"

# stale session time
SESSION_TIMEOUT = timedelta(seconds=1800)
# max session lifetime
SESSION_LIFETIME = timedelta(seconds=28800)
SESSION_COOKIE_NAME = "fence"

# ``JWT_KEYPAIRS`` is an ordered dictionary of entries ``kid:
# (public_key_filename, private_key_filename)`` mapping key ids to keypairs
# used for signing and verifying JWTs issued by fence. NOTE that the filenames
# should be relative to the root directory in fence.
JWT_KEYPAIR_FILES = OrderedDict([
    ('key-01', ('keys/jwt_public_key.pem', 'keys/jwt_private_key.pem')),
])


from local_settings import *
