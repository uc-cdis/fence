from functools import wraps
from random import SystemRandom
from werkzeug.datastructures import ImmutableMultiDict
from userdatamodel.driver import SQLAlchemyDriver
from models import Client, User, Token
from flask import current_app as capp
from flask import request
from flask import Response

import json
import string
import re
import collections
import bcrypt

rng = SystemRandom()
alphanumeric = string.ascii_uppercase + string.ascii_lowercase + string.digits


def random_str(length):
    return ''.join(rng.choice(alphanumeric) for _ in xrange(length))


def json_res(data):
    return Response(json.dumps(data), mimetype='application/json')


def create_client(username, urls, DB, name='', description='', auto_approve=False, is_admin=False):
    driver = SQLAlchemyDriver(DB)
    client_id = random_str(40)
    client_secret = random_str(55)
    hashed_secret = bcrypt.hashpw(client_secret, bcrypt.gensalt())
    with driver.session as s:
        user = s.query(User).filter(User.username == username).first()
        if not user:
            user = User(username=username, is_admin=is_admin)
            s.add(user)
        if s.query(Client).filter(Client.name == name).first():
            raise Exception('client {} already exists'.format(name))
            return
        client = Client(
            client_id=client_id, client_secret=hashed_secret,
            user=user, _redirect_uris=urls,
            description=description, name=name, auto_approve=auto_approve)
        s.add(client)
        s.commit()
    return client_id, client_secret


def drop_client(client_id, db):
    driver = SQLAlchemyDriver(db)
    with driver.session as s:
        tokens = s.query(Token).filter(Token.client_id == client_id)
        tokens.delete()
        clients = s.query(Client).filter(Client.client_id == client_id)
        clients.delete()
        s.commit()


def hash_secret(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.form and 'client_secret' in request.form and 'client_id' in request.form:
            form = request.form.to_dict()
            with capp.db.session as s:
                client = s.query(Client).filter(Client.client_id == form['client_id']).first()
                if client:
                    form['client_secret'] = bcrypt.hashpw(form['client_secret'].encode('utf-8'),
                                                          client.client_secret.encode('utf-8'))
                request.form = ImmutableMultiDict(form)

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
