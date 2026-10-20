import flask
from authlib.oauth2.rfc6749.errors import (
    InvalidGrantError,
    InvalidRequestError,
    UnsupportedGrantTypeError,
)
from authutils.token.core import get_iss
from cdislogging import get_logger

from fence.jwt.validate import validate_jwt
from fence.models import GrantType, IssSubPairToUser
from fence.oidc.token_exchange.base import (
    TOKEN_TYPE_GA4GH_PASSPORT,
    SubjectTokenHandler,
    TokenExchangeResult,
    ValidatedSubjectToken,
)

logger = get_logger(__name__)


class UnsupportedSubjectTokenError(UnsupportedGrantTypeError):
    """
    ``unsupported_grant_type`` for a subject token the grant does not exchange.

    Authlib's ``UnsupportedGrantTypeError`` takes a grant type rather than a
    description, and leaves ``error_description`` out of the response.
    """

    def __init__(self, description):
        super().__init__(GrantType.token_exchange.value)
        self.description = description


class JWTSubjectTokenHandler(SubjectTokenHandler):
    """
    Handle a subject token that is a GA4GH passport, sent as either the generic
    JWT type or the GA4GH passport type. Other JWTs are not exchanged.
    """

    def resolve_issuer(self, subject_token):
        try:
            return get_iss(subject_token)
        except Exception as exc:
            logger.info(f"Could not read 'iss' from subject token: {exc}")
            raise InvalidRequestError("'subject_token' is not a valid JWT")

    def validate(self, subject_token, subject_token_type, issuer):
        """
        Validate the subject token as a GA4GH passport from ``issuer``.

        A passport is validated the same way as the passports Fence accepts at
        the DRS endpoint, except that the acceptable issuer is the single issuer
        whose policy was selected for this request. A JWT that is not a passport
        is rejected once its signature is verified: as ``invalid_grant`` if it
        was sent as a passport, and ``unsupported_grant_type`` otherwise.
        """
        try:
            claims = validate_jwt(
                encoded_token=subject_token,
                attempt_refresh=True,
                require_purpose=False,
                # checked below, once the signature is known to be good
                scope=None,
                issuers=[issuer],
                options={
                    "require_iat": True,
                    "require_exp": True,
                    "verify_aud": False,
                },
            )
        except Exception as exc:
            logger.info(f"Subject token failed validation: {exc}")
            raise InvalidGrantError("The subject token is not acceptable")

        if not claims.get("sub"):
            raise InvalidGrantError("The subject token is missing the 'sub' claim")

        if "ga4gh_passport_v1" not in claims:
            if subject_token_type == TOKEN_TYPE_GA4GH_PASSPORT:
                raise InvalidGrantError("The subject token is not a GA4GH passport")
            raise UnsupportedSubjectTokenError(
                "Non-GA4GH Passport JWT token exchange is not currently supported"
            )

        token_scopes = claims.get("scope") or []
        if isinstance(token_scopes, str):
            token_scopes = token_scopes.split()
        if "openid" not in token_scopes:
            logger.info("Subject token is a passport without the 'openid' scope")
            raise InvalidGrantError("The subject token is not acceptable")

        return ValidatedSubjectToken(
            encoded_token=subject_token,
            issuer=claims["iss"],
            subject=claims["sub"],
            expires_at=int(claims["exp"]),
            claims=claims,
        )

    def exchange(self, validated_token, issuer_policy):
        """
        Sync the authorization described by the passport's visas, then resolve
        the user for the passport's own ``<iss, sub>``.
        """
        from fence.resources.ga4gh.passports import (
            get_or_create_gen3_user_from_iss_sub,
            get_passport_expiration_from_cache,
            sync_gen3_users_authz_from_ga4gh_passports,
        )

        passport = validated_token.encoded_token
        issuer = validated_token.issuer
        subject_id = validated_token.subject

        # this re-validates the passport and every visa in it against
        # GA4GH_VISA_ISSUER_ALLOWLIST, and syncs what the visas assert to
        # Arborist. the duplicated passport validation is intentional: the check
        # in validate is what keeps untrusted issuers out of this code path
        # entirely
        users_from_passport = sync_gen3_users_authz_from_ga4gh_passports([passport])
        if not users_from_passport:
            # no valid visas, or the earliest visa expiration is already too
            # close for the authz removal job to handle
            raise InvalidGrantError(
                "The subject token did not contain any usable GA4GH visas"
            )

        # identity comes from the passport's own <iss, sub>; the visas are
        # treated as authorization only. look the mapping up rather than
        # creating it, so a rejected exchange doesn't leave a user behind -- the
        # sync above already created it for every identity its visas asserted
        db_session = flask.current_app.scoped_session()
        iss_sub_pair = db_session.get(IssSubPairToUser, (issuer, subject_id))
        user = iss_sub_pair.user if iss_sub_pair else None

        require_match = issuer_policy.get("require_passport_subject_visa_match", True)
        if require_match and (not user or user.username not in users_from_passport):
            logger.warning(
                f"Rejecting token exchange: the visas in the passport asserted "
                f"identities {sorted(users_from_passport.keys())}, which do not "
                f"include the passport's own subject. That subject would receive no "
                f"authorization from this exchange."
            )
            raise InvalidGrantError(
                "The subject token's visas do not describe the subject of the "
                "subject token"
            )

        if not user:
            user = get_or_create_gen3_user_from_iss_sub(issuer, subject_id)

        # set by the sync to the earliest expiration among the passport's valid
        # visas, less the authz removal job frequency
        expires_at = validated_token.expires_at
        visa_expiration = get_passport_expiration_from_cache(passport)
        if visa_expiration:
            expires_at = min(expires_at, int(visa_expiration))
        else:
            logger.warning(
                "Could not determine the visa expiration for an exchanged "
                "passport; bounding the issued token by the passport's own "
                "expiration"
            )

        return TokenExchangeResult(user=user, expires_at=expires_at)
