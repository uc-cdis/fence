"""
Provide functionality for blacklisting issued JWT refresh tokens by key id
``jti`` and checking whether key ids are blacklisted.

Attributes:
    BlacklistedToken: class defining table of blacklisted key ids
    blacklist (Callable[[str], None]): blacklist a key id
    is_blacklisted (Callable[[str], bool]):
        return whether key id is blacklisted
"""

import uuid

import flask
import jwt
from sqlalchemy import Column, String
from userdatamodel import Base


class BlacklistedToken(Base):
    """
    Table listing the key ids of tokens to blacklist.
    """

    __tablename__ = 'blacklisted_token'

    # The JWT id `jti` is a UUID4.
    jti = Column(String(36), primary_key=True)


def jti_of_token(token):
    """
    Return just the ``jti`` field from a JWT.

    Args:
        token (str): encoded JWT

    Return:
        str: ``jti`` header from token

    Raises:
        KeyError: if token headers did not contain ``jti`` field
    """
    return jwt.get_unverified_header(token)['jti']


def blacklist_jti(jti):
    """
    Add the JWT id ``jti`` to the blacklist.

    Args:
        jti (str): key id of token to blacklist; must be UUID4

    Return:
        None

    Raises:
        ValueError: if ``jti`` is not a UUID4

    Side Effects:
        - Add entry with ``jti`` to ``BlacklistedToken`` table
    """
    # Check that JWT id is UUID4.
    uuid.UUID(jti, version=4)
    # Return if JWT id is already blacklisted.
    with flask.current_app.db.sesion as session:
        if session.query(BlacklistedToken).filter_by(jti=jti).first():
            return
    # Add JWT id to blacklist table.
    with flask.current_app.db.session as session:
        session.add(BlacklistedToken(jti=jti))
        session.commit()


def blacklist_token(token):
    """
    Compose ``blacklist_jti`` and ``jti_of_token`` to blacklist a token.
    """
    blacklist_jti(jti_of_token(token))


def is_blacklisted(jti):
    """
    Args:
        jti (str):
            JWT id of refresh token to check; should be UUID4 (but won't
            complain if it isn't, returning False)

    Return:
        bool: whether JWT with the given id is blacklisted
    """
    with flask.current_app.db.session as session:
        return bool(session.query(BlacklistedToken).filter_by(jti=jti).first())
