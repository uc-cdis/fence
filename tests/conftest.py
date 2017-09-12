from cdispyutils.hmac4 import get_auth
from cryptography.fernet import Fernet
from flask.testing import make_test_environ_builder
from fence import app as application
from fence import app_init
import pytest
from userdatamodel import Base
from userdatamodel.models import User, HMACKeyPair


@pytest.fixture(scope='session')
def app(request):
    app_init(application, "test_settings")

    def fin():
        for tbl in reversed(Base.metadata.sorted_tables):
            application.db.engine.execute(tbl.delete())
    request.addfinalizer(fin)
    return application


@pytest.fixture
def hmac_header(app):
    with app.db.session as s:
        user = User(username='test')
        s.add(user)
        key = Fernet(app.config['HMAC_ENCRYPTION_KEY'])
        access_key = 'access_key'
        secret_key = 'secret_key'
        keypair = HMACKeyPair(
            access_key=access_key,
            secret_key=key.encrypt(secret_key),
            expire=100, user=user)
        s.add(keypair)

    def build_header(path, method):
        auth = get_auth(access_key, secret_key, path[1:])
        environ = make_test_environ_builder(app, path=path, method=method)
        request = environ.get_request()
        request.headers = dict(request.headers)
        auth.__call__(request)
        return request.headers

    yield build_header

    with app.db.session as s:
        keypair = s.query(HMACKeyPair).filter_by(access_key=access_key).first()
        s.delete(keypair)
