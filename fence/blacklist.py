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
from sqlalchemy import BigInteger, Column, String
from userdatamodel import Base

from . import keys


class BlacklistedToken(Base):
    """
    Table listing the key ids of tokens to blacklist.
    """

    __tablename__ = 'blacklisted_token'

    # The JWT id `jti`, a UUID4.
    jti = Column(String(36), primary_key=True)
    # The expiration in unix time.
    exp = Column(BigInteger)


def blacklist_token(jti, exp):
    """
    Blacklist a token with the JWT id ``jti`` and expiration ``exp``.

    Args:
        jti (str): JWT id, which must be a UUID4
        exp (int): the expiration time of the token

    Return:
        None

    Side Effects:
        - Add entry with ``jti`` to ``BlacklistedToken`` table
    """
    # Do nothing if JWT id is already blacklisted.
    with flask.current_app.db.sesion as session:
        if session.query(BlacklistedToken).filter_by(jti=jti).first():
            return
    # Add JWT id to blacklist table.
    with flask.current_app.db.session as session:
        session.add(BlacklistedToken(jti=jti, exp=exp))
        session.commit()


def blacklist_encoded_token(encoded_token, public_key=None):
    """
    Given an encoded refresh JWT ``encoded_token``, add it to the blacklist
    using its JWT id ``jti`` and expiration ``exp``.

    This just wraps ``blacklist_token`` by decoding the token first. The token
    _must_ be a refresh token; only refresh tokens may be blacklisted.

    Args:
        encoded_token (str): the token
        public_key (Optional[str]): public key to decode token with

    Return:
        None

    Raises:
        - KeyError: if token is missing a claim (``aud``, ``exp``, or ``jti``)
        - ValueError: if ``jti`` is not UUID4, ``exp`` not provided
        - jwt.InvalidTokenError: if token decoding fails

    Side Effects:
        - Add entry with ``jti`` to ``BlacklistedToken`` table
    """
    # Decode token and get claims.
    public_key = public_key or keys.get_default_private_key()
    token = jwt.decode(encoded_token, public_key, algorithm='RS256')
    jti = token['jti']
    exp = token['exp']
    aud = token['aud']

    # Do checks.
    # Check that JWT id is UUID4 (this raises a ValueError otherwise).
    uuid.UUID(jti, version=4)
    # Must be refresh token.
    if 'refresh' not in aud:
        raise ValueError('can only blacklist refresh tokens')

    blacklist_token(jti, exp)


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
