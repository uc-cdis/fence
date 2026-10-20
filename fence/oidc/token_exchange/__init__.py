from authlib.oauth2.rfc6749.errors import InvalidRequestError

from fence.oidc.token_exchange.base import (
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_GA4GH_PASSPORT,
    TOKEN_TYPE_JWT,
)
from fence.oidc.token_exchange.requested_handlers import (
    AccessTokenRequestedTokenHandler,
)
from fence.oidc.token_exchange.subject_handlers import JWTSubjectTokenHandler

SUBJECT_TOKEN_HANDLERS = {
    TOKEN_TYPE_JWT: JWTSubjectTokenHandler,
    TOKEN_TYPE_GA4GH_PASSPORT: JWTSubjectTokenHandler,
}

REQUESTED_TOKEN_HANDLERS = {
    TOKEN_TYPE_ACCESS_TOKEN: AccessTokenRequestedTokenHandler,
}


def get_subject_token_handler(token_type):
    """
    Return:
        SubjectTokenHandler: the handler registered for ``token_type``

    Raises:
        InvalidRequestError: if no handler is registered for ``token_type``
    """
    handler_cls = SUBJECT_TOKEN_HANDLERS.get(token_type)
    if not handler_cls:
        raise InvalidRequestError(f"Unsupported 'subject_token_type={token_type}'")
    return handler_cls()


def get_requested_token_handler(token_type):
    """
    Return:
        RequestedTokenHandler: the handler registered for ``token_type``

    Raises:
        InvalidRequestError: if no handler is registered for ``token_type``
    """
    handler_cls = REQUESTED_TOKEN_HANDLERS.get(token_type)
    if not handler_cls:
        raise InvalidRequestError(f"Unsupported 'requested_token_type={token_type}'")
    return handler_cls()
