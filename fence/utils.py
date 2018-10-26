import bcrypt
import collections
from functools import wraps
import json
from random import SystemRandom
import re
import string
import requests
from sqlalchemy import func
from urllib import urlencode
from urlparse import parse_qs, urlsplit, urlunsplit

import flask
from userdatamodel.driver import SQLAlchemyDriver
from werkzeug.datastructures import ImmutableMultiDict

from fence.models import Client, GrantType, User
from fence.jwt.token import CLIENT_ALLOWED_SCOPES


rng = SystemRandom()
alphanumeric = string.ascii_uppercase + string.ascii_lowercase + string.digits


def random_str(length):
    return "".join(rng.choice(alphanumeric) for _ in xrange(length))


def json_res(data):
    return flask.Response(json.dumps(data), mimetype="application/json")


def create_client(
    username,
    urls,
    DB,
    name="",
    description="",
    auto_approve=False,
    is_admin=False,
    grant_types=None,
    confidential=True,
):
    grant_types = grant_types
    driver = SQLAlchemyDriver(DB)
    client_id = random_str(40)
    client_secret = None
    hashed_secret = None
    if confidential:
        client_secret = random_str(55)
        hashed_secret = bcrypt.hashpw(client_secret, bcrypt.gensalt())
    auth_method = "client_secret_basic" if confidential else "none"
    with driver.session as s:
        user = (
            s.query(User).filter(func.lower(User.username) == username.lower()).first()
        )
        if not user:
            user = User(username=username, is_admin=is_admin)
            s.add(user)
        if s.query(Client).filter(Client.name == name).first():
            raise Exception("client {} already exists".format(name))
        client = Client(
            client_id=client_id,
            client_secret=hashed_secret,
            user=user,
            redirect_uris=urls,
            _allowed_scopes=" ".join(CLIENT_ALLOWED_SCOPES),
            description=description,
            name=name,
            auto_approve=auto_approve,
            grant_types=grant_types,
            is_confidential=confidential,
            token_endpoint_auth_method=auth_method,
        )
        s.add(client)
        s.commit()
    return client_id, client_secret


def hash_secret(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        has_secret = "client_secret" in flask.request.form
        has_client_id = "client_id" in flask.request.form
        if flask.request.form and has_secret and has_client_id:
            form = flask.request.form.to_dict()
            with flask.current_app.db.session as session:
                client = (
                    session.query(Client)
                    .filter(Client.client_id == form["client_id"])
                    .first()
                )
                if client:
                    form["client_secret"] = bcrypt.hashpw(
                        form["client_secret"].encode("utf-8"),
                        client.client_secret.encode("utf-8"),
                    )
                flask.request.form = ImmutableMultiDict(form)

        return f(*args, **kwargs)

    return wrapper


def wrap_list_required(f):
    @wraps(f)
    def wrapper(d, *args, **kwargs):
        data_is_a_list = False
        if isinstance(d, list):
            d = {"data": d}
            data_is_a_list = True
        if not data_is_a_list:
            return f(d, *args, **kwargs)
        else:
            result = f(d, *args, **kwargs)
            return result["data"]

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
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", s)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def strip(s):
    if isinstance(s, str):
        return s.strip()
    return s


def clear_cookies(response):
    """
    Set all cookies to empty and expired.
    """
    for cookie_name in flask.request.cookies.keys():
        response.set_cookie(cookie_name, "", expires=0)


def get_error_params(error, description):
    params = ""
    if error:
        args = {"error": error, "error_description": description}
        params = urlencode(args)
    return params


def append_query_params(original_url, **kwargs):
    """
    Add additional query string arguments to the given url.

    Example call:
        new_url = append_query_params(
            original_url, error='this is an error',
            another_arg='this is another argument')
    """
    scheme, netloc, path, query_string, fragment = urlsplit(original_url)
    query_params = parse_qs(query_string)
    if kwargs is not None:
        for key, value in kwargs.iteritems():
            query_params[key] = [value]

    new_query_string = urlencode(query_params, doseq=True)
    new_url = urlunsplit((scheme, netloc, path, new_query_string, fragment))
    return new_url


def split_url_and_query_params(url):
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_params = parse_qs(query_string)
    url = urlunsplit((scheme, netloc, path, None, fragment))
    return url, query_params


def send_email(from_email, to_emails, subject, text, smtp_domain):
    """
    Send email to group of emails using mail gun api.

    https://app.mailgun.com/

    Args:
        from_email(str): from email
        to_emails(list): list of emails to receive the messages
        text(str): the text message
        smtp_domain(dict): smtp domain server

            {
                "smtp_hostname": "smtp.mailgun.org",
                "default_login": "postmaster@mailgun.planx-pla.net",
                "api_url": "https://api.mailgun.net/v3/mailgun.planx-pla.net",
                "smtp_password": password",
                "api_key": "api key"
            }

    Returns:
        Http response

    Exceptions:
        KeyError

    """
    from fence.settings import GUN_MAIL

    api_key = GUN_MAIL[smtp_domain]["api_key"]
    email_url = GUN_MAIL[smtp_domain]["api_url"] + "/messages"

    return requests.post(
        email_url,
        auth=("api", api_key),
        data={"from": from_email, "to": to_emails, "subject": subject, "text": text},
    )
