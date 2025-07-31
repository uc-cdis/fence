import bcrypt
import collections
from functools import wraps
import logging
import json
from random import SystemRandom
import re
import string
import requests
import boto3
from urllib.parse import urlencode
from urllib.parse import parse_qs, urlsplit, urlunsplit
import sys

from cdislogging import get_logger
import flask
from werkzeug.datastructures import ImmutableMultiDict

from fence.models import Client, User, query_for_user
from fence.errors import NotFound, UserError
from fence.config import config
from authlib.oauth2.rfc6749.util import scope_to_list
from authlib.oauth2.rfc6749.errors import InvalidScopeError

rng = SystemRandom()
alphanumeric = string.ascii_uppercase + string.ascii_lowercase + string.digits
logger = get_logger(__name__)


def random_str(length):
    return "".join(rng.choice(alphanumeric) for _ in range(length))


def json_res(data):
    return flask.Response(json.dumps(data), mimetype="application/json")


def fetch_url_data(url: str, format: str, expected_status_code: int = 200) -> str:
    """
    Perform a GET request and return the raw response data.
    Using this function instead of making the request directly in the caller function allows us
    to mock the returned data in unit tests.

    Args:
        url (str): URL to GET

    Returns:
        str: raw response data
    """
    res = requests.get(url)
    assert res.status_code == expected_status_code, f"Unable to fetch data from '{url}'"
    if format == "text":
        return res.text
    elif format == "json":
        return res.json()
    raise Exception(f"Unknown 'fetch_url_data' format '{format}'")


def generate_client_credentials(confidential):
    """
    Generate a new client ID. If the client is confidential, also generate a new client secret.
    The unhashed secret should be returned to the user and the hashed secret should be stored
    in the database for later use.

    Args:
        confidential (bool): true if the client is confidential, false if it is public

    Returns:
        tuple: (client ID, unhashed client secret or None, hashed client secret or None)
    """
    client_id = random_str(40)
    client_secret = None
    hashed_secret = None
    if confidential:
        client_secret = random_str(55)
        hashed_secret = bcrypt.hashpw(
            client_secret.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
    return client_id, client_secret, hashed_secret


def create_client(
    DB,
    username=None,
    urls=[],
    name="",
    description="",
    auto_approve=False,
    is_admin=False,
    grant_types=None,
    confidential=True,
    arborist=None,
    policies=None,
    allowed_scopes=None,
    expires_in=None,
):
    client_id, client_secret, hashed_secret = generate_client_credentials(confidential)
    if arborist is not None:
        arborist.create_client(client_id, policies)
    driver = get_SQLAlchemyDriver(DB)
    auth_method = "client_secret_basic" if confidential else "none"

    allowed_scopes = allowed_scopes or config["CLIENT_ALLOWED_SCOPES"]
    if not set(allowed_scopes).issubset(set(config["CLIENT_ALLOWED_SCOPES"])):
        raise ValueError(
            "Each allowed scope must be one of: {}".format(
                config["CLIENT_ALLOWED_SCOPES"]
            )
        )

    if "openid" not in allowed_scopes:
        allowed_scopes.append("openid")
        logger.warning('Adding required "openid" scope to list of allowed scopes.')

    with driver.session as s:
        user = None
        if username:
            user = query_for_user(session=s, username=username)
            if not user:
                user = User(username=username, is_admin=is_admin)
                s.add(user)

        if s.query(Client).filter(Client.name == name).first():
            if arborist is not None:
                arborist.delete_client(client_id)
            raise Exception("client {} already exists".format(name))

        client = Client(
            client_id=client_id,
            client_secret=hashed_secret,
            user=user,
            redirect_uris=urls,
            allowed_scopes=" ".join(allowed_scopes),
            description=description,
            name=name,
            auto_approve=auto_approve,
            grant_types=grant_types,
            is_confidential=confidential,
            token_endpoint_auth_method=auth_method,
            expires_in=expires_in,
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
                    ).decode("utf-8")
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
    for k, v in d.items():
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
    for k, v in d.items():
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
    for cookie_name in list(flask.request.cookies.keys()):
        response.set_cookie(key=cookie_name, value="", expires=0, httponly=True)


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
        for key, value in kwargs.items():
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
                "smtp_password": "password", # pragma: allowlist secret
                "api_key": "api key" # pragma: allowlist secret
            }

    Returns:
        Http response

    Exceptions:
        KeyError

    """
    if smtp_domain not in config["GUN_MAIL"] or not config["GUN_MAIL"].get(
        smtp_domain
    ).get("smtp_password"):
        raise NotFound(
            "SMTP Domain '{}' does not exist in configuration for GUN_MAIL or "
            "smtp_password was not provided. "
            "Cannot send email.".format(smtp_domain)
        )

    api_key = config["GUN_MAIL"][smtp_domain].get("api_key", "")
    email_url = config["GUN_MAIL"][smtp_domain].get("api_url", "") + "/messages"

    return requests.post(
        email_url,
        auth=("api", api_key),
        data={"from": from_email, "to": to_emails, "subject": subject, "text": text},
    )

def send_email_ses(body, to_emails, subject):
    """
    Send email to group of emails using AWS SES api.

    Args:
        from_email(str): from email
        to_emails(list): list of emails to receive the messages
        text(str): the text message
        smtp_domain(dict): smtp domain server

            {
                "smtp_hostname": "smtp.mailgun.org",
                "default_login": "postmaster@mailgun.planx-pla.net",
                "api_url": "https://api.mailgun.net/v3/mailgun.planx-pla.net",
                "smtp_password": "password",
                "api_key": "api key"
            }

    Returns:
        Http response

    Exceptions:
        KeyError

    """
    #TODO add import for boto

    if not config["AWS_SES"]:
        raise NotFound("AWS SES '{}' does not exist in configuration. Cannot send email.")
    if "SENDER" not in config["AWS_SES"]:
        raise NotFound("AWS SES sender does not exist in configuration. Cannot send email.")
    if "AWS_ACCESS_KEY" not in config["AWS_SES"] or "AWS_SECRET_KEY" not in config["AWS_SES"]:
        raise NotFound("AWS SES credentials are missing in configuration. Cannot send email.")

    #TODO retrieve body from template (pass as external param above)
    if not body:
        raise Exception('You must provide a text or html body.')
    if not subject:
        raise Exception('You must provide a text subject for the email.')

    sender = config["AWS_SES"]["SENDER"]
    AWS_ACCESS_KEY = config["AWS_SES"]["AWS_ACCESS_KEY"]
    AWS_SECRET_KEY = config["AWS_SES"]["AWS_SECRET_KEY"]
    region = config["AWS_SES"]["AWS_REGION"] if config["AWS_SES"]["AWS_REGION"] is not None else "us-east-1"
    #TODO get a general team email for this
    RECIPIENT = config["AWS_SES"]["RECIPIENT"] if config["AWS_SES"]["RECIPIENT"] is not None else "lgraglia@uchicago.edu"
        
        # if not self._html:
        #     self._format = 'text'
        #     body = self._text

    client = boto3.client(
        'ses',
        region_name=region,
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY
    )
    try:
        response = client.send_email(
            Destination={
                'ToAddresses': [RECIPIENT],
            },
            Message={
                'Body': {
                    'Text': {
                        'Charset': 'UTF-8',
                        'Data': body,
                    },
                },
                'Subject': {
                    'Charset': 'UTF-8',
                    'Data': subject,
                },
            },
            Source=sender,
        )
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent! Message ID:"),
        print(response['MessageId'])
    logging.warning(json.dumps(response))
    return response

def get_valid_expiration_from_request(
    expiry_param="expires_in", max_limit=None, default=None
):
    """
    Thin wrapper around get_valid_expiration; looks for default query parameter "expires_in"
    in flask request, unless a different parameter name was specified.
    """
    return get_valid_expiration(
        flask.request.args.get(expiry_param), max_limit=max_limit, default=default
    )


def get_valid_expiration(requested_expiration, max_limit=None, default=None):
    """
    If requested_expiration is not a positive integer and not None, throw error.
    If max_limit is provided and requested_expiration exceeds max_limit,
      return max_limit.
    If requested_expiration is None, return default (which may also be None).
    Else return requested_expiration.
    """
    if requested_expiration is None:
        return default
    try:
        rv = int(requested_expiration)
        assert rv > 0
        if max_limit:
            rv = min(rv, max_limit)
        return rv
    except (ValueError, AssertionError):
        raise UserError(
            "Requested expiry must be a positive integer; instead got {}".format(
                requested_expiration
            )
        )


def _print_func_name(function):
    return "{}.{}".format(function.__module__, function.__name__)


def _print_kwargs(kwargs):
    return ", ".join("{}={}".format(k, repr(v)) for k, v in list(kwargs.items()))


def log_backoff_retry(details):
    args_str = ", ".join(map(str, details["args"]))
    kwargs_str = (
        (", " + _print_kwargs(details["kwargs"])) if details.get("kwargs") else ""
    )
    func_call_log = "{}({}{})".format(
        _print_func_name(details["target"]), args_str, kwargs_str
    )
    logging.warning(
        "backoff: call {func_call} delay {wait:0.1f} seconds after {tries} tries".format(
            func_call=func_call_log, **details
        )
    )


def log_backoff_giveup(details):
    args_str = ", ".join(map(str, details["args"]))
    kwargs_str = (
        (", " + _print_kwargs(details["kwargs"])) if details.get("kwargs") else ""
    )
    func_call_log = "{}({}{})".format(
        _print_func_name(details["target"]), args_str, kwargs_str
    )
    logging.error(
        "backoff: gave up call {func_call} after {tries} tries; exception: {exc}".format(
            func_call=func_call_log, exc=sys.exc_info(), **details
        )
    )


def exception_do_not_retry(error):
    def _is_status(code):
        return (
            str(getattr(error, "code", None)) == code
            or str(getattr(error, "status", None)) == code
            or str(getattr(error, "status_code", None)) == code
        )

    if _is_status("409") or _is_status("404"):
        return True

    return False


def get_from_cache(item_id, memory_cache, db_cache_table, db_cache_table_id_field="id"):
    """
    Attempt to get a cached item and store in memory cache from db if necessary.

    NOTE: This requires custom implementation for putting items in the db cache table.
    """
    # try to retrieve from local in-memory cache
    rv, expires_at = memory_cache.get(item_id, (None, 0))
    if expires_at > expiry:
        return rv

    # try to retrieve from database cache
    if hasattr(flask.current_app, "db"):  # we don't have db in startup
        with flask.current_app.db.session as session:
            cache = (
                session.query(db_cache_table)
                .filter(
                    getattr(db_cache_table, db_cache_table_id_field, None) == item_id
                )
                .first()
            )
            if cache and cache.expires_at and cache.expires_at > expiry:
                rv = dict(cache)

                # store in memory cache
                memory_cache[item_id] = rv, cache.expires_at
                return rv


def get_SQLAlchemyDriver(db_conn_url):
    from userdatamodel.driver import SQLAlchemyDriver

    # override userdatamodel's `setup_db` function which creates tables
    # and runs database migrations, because Alembic handles that now.
    # TODO move userdatamodel code to Fence and remove dependencies to it
    SQLAlchemyDriver.setup_db = lambda _: None
    return SQLAlchemyDriver(db_conn_url)


# Default settings to control usage of backoff library.
DEFAULT_BACKOFF_SETTINGS = {
    "on_backoff": log_backoff_retry,
    "on_giveup": log_backoff_giveup,
    "max_tries": config["DEFAULT_BACKOFF_SETTINGS_MAX_TRIES"],
    "giveup": exception_do_not_retry,
}


def validate_scopes(request_scopes, client):
    if not client:
        raise Exception("Client object is None")

    if request_scopes:
        scopes = scope_to_list(request_scopes)
        # can we get some debug logs here that log the client, what scopes they have, and what scopes were requested
        if not client.check_requested_scopes(set(scopes)):
            logger.debug(
                "Request Scope are "
                + " ".join(scopes)
                + " but client supported scopes are "
                + client.scope
            )
            raise InvalidScopeError("Failed to Authorize due to unsupported scope")

    return True
