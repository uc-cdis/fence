"""
Track DPoP proof `jti` values so that a proof cannot be replayed.
"""

import time

import flask
from authutils.dpop import DPOP_PROOF_MAX_TTL
from sqlalchemy.exc import IntegrityError

from fence.models import DPoPProofJTI


def jti_seen(jti):
    """
    Record a DPoP proof id and report whether it had already been used.

    Suitable as the `jti_seen_callback` for
    `authutils.dpop.validate_dpop_proof`, which rejects the proof when this
    returns True.

    Args:
        jti (str): the `jti` claim of the DPoP proof being validated

    Return:
        bool: whether this `jti` had already been recorded
    """
    now = int(time.time())
    with flask.current_app.db.session as session:
        # A proof older than this is rejected on `iat` alone, so its id stops mattering.
        session.query(DPoPProofJTI).filter(DPoPProofJTI.exp < now).delete()
        session.add(DPoPProofJTI(jti=jti, exp=now + DPOP_PROOF_MAX_TTL))
        try:
            # The insert is what detects the replay: the primary key makes it fail for
            # the second caller even when two requests race in separate processes.
            session.commit()
        except IntegrityError:
            session.rollback()
            return True
    return False
