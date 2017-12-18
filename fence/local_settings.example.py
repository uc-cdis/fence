from boto.s3.connection import OrdinaryCallingFormat
DB = 'postgresql://test:test@localhost:5432/fence'

MOCK_AUTH = False
MOCK_STORAGE = False

HOSTNAME = ''
APPLICATION_ROOT = '/user'

EMAIL_SERVER = 'localhost'

SEND_FROM = 'phillis.tt@gmail.com'

SEND_TO = 'phillis.tt@gmail.com'

HMAC_ENCRYPTION_KEY = ''

OPENID_CONNECT = {
    'google': {
        'client_id': '',
        'client_secret': '',
        'redirect_url': ''
    }
}

STORAGE_CREDENTIALS = {
    "cleversafe": {
        'aws_access_key_id': '',
        'aws_secret_access_key': '',
        'host': 'somemanager.osdc.io',
        'public_host': 'someobjstore.datacommons.io',
        'port': 443,
        'is_secure': True,
        'username': 'someone',
        'password': 'somepass',
        "calling_format": OrdinaryCallingFormat(),
        "is_mocked": True
    }
}


'''
If the api is behind firewall that need to set http proxy:
    HTTP_PROXY = {'host': 'cloud-proxy', 'port': 3128}
'''
HTTP_PROXY = None

STORAGES = ['/cleversafe']
ITRUST_GLOBAL_LOGOUT = 'https://itrusteauth.nih.gov/siteminderagent/smlogout.asp?mode=nih&AppReturnUrl='
SESSION_COOKIE_SECURE = False
ENABLE_CSRF_PROTECTION = True
