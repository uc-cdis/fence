import flask
from flask_sqlalchemy_session import current_session

from fence.jwt.token import (
    AuthFlowTypes,
    generate_signed_access_token,
    generate_signed_id_token,
    generate_signed_refresh_token,
)
from fence.models import AuthorizationCode, User
from fence.oidc.errors import OIDCError
from fence.resources.google.utils import (
    get_linked_google_account_email,
    get_linked_google_account_exp,
)

from fence.config import config


def generate_token(client, grant_type, **kwargs):
    """
    Generate the token response, which looks like the following:

        {
            'token_type': 'Bearer',
            'id_token': 'eyJhb[...long encoded JWT...]OnoVQ',
            'access_token': 'eyJhb[...long encoded JWT...]evfxA',
            'refresh_token': 'eyJhb[ ... long encoded JWT ... ]KnLJA',
            'expires_in': 1200,
        }

    This function will be called in authlib internals.

    Args:
        client: not used (would be used to determine expiration)
        grant_type: not used
        expires_in: not used (see expiration times configured above)
        scope (List[str]): list of requested scopes
        include_refresh_token: not used
        nonce (str): "nonsense" to include in ID token (see OIDC spec)
        refresh_token:
            for a refresh token grant, pass in the previous refresh token
            to return that same token again instead of generating a new one
            (otherwise this will let the refresh token refresh itself)
        refresh_token_claims (dict):
            also for a refresh token grant, pass the previous refresh token
            claims (to avoid having to encode or decode the refresh token
            here)
    """
    if grant_type == "authorization_code" or grant_type == "refresh_token":
        return generate_token_response(client, grant_type, **kwargs)
    elif grant_type == "implicit":
        return generate_implicit_response(client, grant_type, **kwargs)
    elif grant_type == "client_credentials":
        return generate_client_response(client, **kwargs)


def generate_implicit_response(
    client,
    grant_type,
    include_access_token=True,
    expires_in=None,
    user=None,
    scope=None,
    nonce=None,
    **kwargs
):
    """
    Generate the token response for the "implicit" grant.

    Return:
        dict: token response
            {
                "token_type": "Bearer",
                "id_token": "",
                "access_token": "",
                "expires_in": 1200,
            }
    """
    # prevent those bothersome "not bound to session" errors
    if user not in current_session:
        user = current_session.query(User).filter_by(id=user.id).first()

    if not user:
        raise OIDCError("user not authenticated")

    keypair = flask.current_app.keypairs[0]

    linked_google_email = get_linked_google_account_email(user.id)
    linked_google_account_exp = get_linked_google_account_exp(user.id)

    if not isinstance(scope, list):
        scope = scope.split(" ")

    if not "user" in scope:
        scope.append("user")

    # ``expires_in`` is just the token expiration time.
    expires_in = config["ACCESS_TOKEN_EXPIRES_IN"]

    response = {
        "token_type": "Bearer",
        "expires_in": expires_in,
        # "state" handled in authlib
    }

    # don't provide user projects access in access_tokens for implicit flow
    # due to issues with "Location" header size during redirect (and b/c
    # of general deprecation of user access information in tokens)
    if include_access_token:
        access_token = generate_signed_access_token(
            kid=keypair.kid,
            private_key=keypair.private_key,
            user=user,
            expires_in=config["ACCESS_TOKEN_EXPIRES_IN"],
            scopes=scope,
            client_id=client.client_id,
            linked_google_email=linked_google_email,
        ).token
        response["access_token"] = access_token

    # don't provide user projects access in id_tokens for implicit flow
    # due to issues with "Location" header size during redirect (and b/c
    # of general deprecation of user access information in tokens)
    id_token = generate_signed_id_token(
        kid=keypair.kid,
        private_key=keypair.private_key,
        user=user,
        expires_in=config["ACCESS_TOKEN_EXPIRES_IN"],
        client_id=client.client_id,
        scopes=scope,
        nonce=nonce,
        linked_google_email=linked_google_email,
        linked_google_account_exp=linked_google_account_exp,
        include_project_access=False,
        auth_flow_type=AuthFlowTypes.IMPLICIT,
        access_token=access_token if include_access_token else None,
    ).token
    response["id_token"] = id_token

    return response


def generate_token_response(
    client,
    grant_type,
    expires_in=None,
    refresh_token_expires_in=None,
    user=None,
    scope=None,
    include_refresh_token=True,
    nonce=None,
    refresh_token=None,
    refresh_token_claims=None,
    **kwargs
):
    """
    Generate the token response for the "authorization_code" and
    "refresh_token" grants.

    Return:
        dict: token response
            {
                "token_type": "Bearer",
                "id_token": "",
                "access_token": "",
                "refresh_token": "",
                "expires_in": 1200,
            }
    """
    # prevent those bothersome "not bound to session" errors
    if user not in current_session:
        user = current_session.query(User).filter_by(id=user.id).first()

    if not user:
        # Find the ``User`` model.
        # The way to do this depends on the grant type.
        if grant_type == "authorization_code":
            # For authorization code grant, get the code from either the query
            # string or the form data, and use that to look up the user.
            if flask.request.method == "GET":
                code = flask.request.args.get("code")
            else:
                code = flask.request.form.get("code")
            user = (
                current_session.query(AuthorizationCode)
                .filter_by(code=code)
                .first()
                .user
            )
        if grant_type == "refresh_token":
            # For refresh token, the user ID is the ``sub`` field in the token.
            user = (
                current_session.query(User)
                .filter_by(id=int(refresh_token_claims["sub"]))
                .first()
            )

    keypair = flask.current_app.keypairs[0]

    linked_google_email = get_linked_google_account_email(user.id)
    linked_google_account_exp = get_linked_google_account_exp(user.id)

    if not isinstance(scope, list):
        scope = scope.split(" ")

    access_token = generate_signed_access_token(
        kid=keypair.kid,
        private_key=keypair.private_key,
        user=user,
        expires_in=config["ACCESS_TOKEN_EXPIRES_IN"],
        scopes=scope,
        client_id=client.client_id,
        linked_google_email=linked_google_email,
    ).token
    id_token = generate_signed_id_token(
        kid=keypair.kid,
        private_key=keypair.private_key,
        user=user,
        expires_in=config["ACCESS_TOKEN_EXPIRES_IN"],
        client_id=client.client_id,
        scopes=scope,
        nonce=nonce,
        linked_google_email=linked_google_email,
        linked_google_account_exp=linked_google_account_exp,
        auth_flow_type=AuthFlowTypes.CODE,
        access_token=access_token,
    ).token
    # If ``refresh_token`` was passed (for instance from the refresh
    # grant), use that instead of generating a new one.
    if refresh_token is None:
        if refresh_token_expires_in is None:
            refresh_token_expires_in = config["REFRESH_TOKEN_EXPIRES_IN"]
        refresh_token = generate_signed_refresh_token(
            kid=keypair.kid,
            private_key=keypair.private_key,
            user=user,
            expires_in=refresh_token_expires_in,
            scopes=scope,
            client_id=client.client_id,
        ).token
    # ``expires_in`` is just the access token expiration time.
    expires_in = config["ACCESS_TOKEN_EXPIRES_IN"]
    return {
        "token_type": "Bearer",
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
    }


def generate_client_response(client, expires_in=None, scope=None, **kwargs):
    """
    Generate the token response for the "client_credentials" grant.

    Args:
        client (Client): OIDC client that initiated the request
        expires_in (int): Optional (default: configurable
            `ACCESS_TOKEN_EXPIRES_IN`) - token lifetime in seconds
        scope (List[str]): list of requested scopes

    Return:
        dict: token response
            {
                "token_type": "Bearer",
                "access_token": "",
                "expires_in": 1200,
            }
    """
    keypair = flask.current_app.keypairs[0]
    expires_in = config["ACCESS_TOKEN_EXPIRES_IN"] or expires_in

    scope = scope or []
    if not isinstance(scope, list):
        scope = scope.split(" ")

    access_token = generate_signed_access_token(
        kid=keypair.kid,
        private_key=keypair.private_key,
        expires_in=expires_in,
        scopes=scope,
        client_id=client.client_id,
    ).token
    return {
        "token_type": "Bearer",
        "access_token": access_token,
        "expires_in": expires_in,
    }
