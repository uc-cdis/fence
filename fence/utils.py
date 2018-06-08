import bcrypt
import collections
from functools import wraps
import json
from random import SystemRandom
import re
import string
from sqlalchemy import func
import flask
from userdatamodel.driver import SQLAlchemyDriver
from werkzeug.datastructures import ImmutableMultiDict
from flask_sqlalchemy_session import current_session

from fence.models import Client, User, UserGoogleAccount
from fence.jwt.token import CLIENT_ALLOWED_SCOPES

rng = SystemRandom()
alphanumeric = string.ascii_uppercase + string.ascii_lowercase + string.digits


def random_str(length):
    return ''.join(rng.choice(alphanumeric) for _ in xrange(length))


def json_res(data):
    return flask.Response(json.dumps(data), mimetype='application/json')


def create_client(
        username, urls, DB, name='', description='', auto_approve=False,
        is_admin=False):
    driver = SQLAlchemyDriver(DB)
    client_id = random_str(40)
    client_secret = random_str(55)
    hashed_secret = bcrypt.hashpw(client_secret, bcrypt.gensalt())
    with driver.session as s:
        user = s.query(User).filter(func.lower(User.username) == username.lower()).first()
        if not user:
            user = User(username=username, is_admin=is_admin)
            s.add(user)
        if s.query(Client).filter(Client.name == name).first():
            raise Exception('client {} already exists'.format(name))
            return
        client = Client(
            client_id=client_id, client_secret=hashed_secret,
            user=user, _redirect_uris=urls,
            _allowed_scopes=' '.join(CLIENT_ALLOWED_SCOPES),
            description=description, name=name, auto_approve=auto_approve)
        s.add(client)
        s.commit()
    return client_id, client_secret


def drop_client(client_name, db):
    driver = SQLAlchemyDriver(db)
    with driver.session as s:
        clients = s.query(Client).filter(Client.name == client_name)
        clients.delete()
        s.commit()


def hash_secret(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        has_secret = 'client_secret' in flask.request.form
        has_client_id = 'client_id' in flask.request.form
        if flask.request.form and has_secret and has_client_id:
            form = flask.request.form.to_dict()
            with flask.current_app.db.session as session:
                client = (
                    session
                    .query(Client)
                    .filter(Client.client_id == form['client_id'])
                    .first()
                )
                if client:
                    form['client_secret'] = bcrypt.hashpw(
                        form['client_secret'].encode('utf-8'),
                        client.client_secret.encode('utf-8')
                    )
                flask.request.form = ImmutableMultiDict(form)

        return f(*args, **kwargs)

    return wrapper


def wrap_list_required(f):
    @wraps(f)
    def wrapper(d, *args, **kwargs):
        data_is_a_list = False
        if isinstance(d, list):
            d = {'data': d}
            data_is_a_list = True
        if not data_is_a_list:
            return f(d, *args, **kwargs)
        else:
            result = f(d, *args, **kwargs)
            return result['data']
    return wrapper


@wrap_list_required
def convert_key(d, converter):
    if isinstance(d, str) or not isinstance(d, collections.Iterable):
        return d

    new = {}
    for k, v in d.iteritems():
        new_v = v
        if isinstance(v, dict):
            new_v = convert_key(v, converter)
        elif isinstance(v, list):
            new_v = list()
            for x in v:
                new_v.append(convert_key(x, converter))
        new[converter(k)] = new_v
    return new


@wrap_list_required
def convert_value(d, converter):
    if isinstance(d, str) or not isinstance(d, collections.Iterable):
        return converter(d)

    new = {}
    for k, v in d.iteritems():
        new_v = v
        if isinstance(v, dict):
            new_v = convert_value(v, converter)
        elif isinstance(v, list):
            new_v = list()
            for x in v:
                new_v.append(convert_value(x, converter))
        new[k] = converter(new_v)
    return new


def to_underscore(s):
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', s)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def strip(s):
    if isinstance(s, str):
        return s.strip()
    return s


def clear_cookies(response):
    """
    Set all cookies to empty and expired.
    """
    for cookie_name in flask.request.cookies.values():
        response.set_cookie(cookie_name, '', expires=0)
