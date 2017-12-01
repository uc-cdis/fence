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


def blacklist_token(token, private_key=None):
    """
    Add the JWT id ``jti`` to the blacklist.

    Args:
        token (str): encoded form of token to blacklist
        private_key (Optional[str]): private key to decode with

    Return:
        None

    Raises:
        - ValueError: if ``jti`` is not a UUID4
        - jwt.InvalidTokenError: if token decoding fails

    Side Effects:
        - Add entry with ``jti`` to ``BlacklistedToken`` table
    """
    private_key = private_key or keys.get_default_private_key()
    decoded_token = jwt.decode(token, private_key, algorithm='RS256')
    exp = decoded_token['exp']
    jti = decoded_token['jti']
    # Check that JWT id is UUID4 (this raises a ValueError otherwise).
    uuid.UUID(jti, version=4)
    # Do nothing if JWT id is already blacklisted.
    with flask.current_app.db.sesion as session:
        if session.query(BlacklistedToken).filter_by(jti=jti).first():
            return
    # Add JWT id to blacklist table.
    with flask.current_app.db.session as session:
        session.add(BlacklistedToken(jti=jti, exp=exp))
        session.commit()


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
