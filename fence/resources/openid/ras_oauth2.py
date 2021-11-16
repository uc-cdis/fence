import backoff
import flask
import requests

# the whole passports module is imported to avoid issue with circular imports
import fence.resources.ga4gh.passports

from flask_sqlalchemy_session import current_session
from jose import jwt as jose_jwt

from authutils.errors import JWTError
from authutils.token.core import get_iss, get_kid


from fence.config import config
from fence.models import (
    GA4GHVisaV1,
    IdentityProvider,
    User,
    IssSubPairToUser,
    query_for_user,
    create_user,
)
from fence.jwt.validate import validate_jwt
from fence.utils import DEFAULT_BACKOFF_SETTINGS
from .idp_oauth2 import Oauth2ClientBase


class RASOauth2Client(Oauth2ClientBase):
    """
    client for interacting with RAS oauth 2,
    as openid connect is supported under oauth2
    """

    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(RASOauth2Client, self).__init__(
            settings,
            logger,
            scope="openid ga4gh_passport_v1 email profile",
            discovery_url=settings.get(
                "discovery_url", "https://sts.nih.gov/.well-known/openid-configuration"
            ),
            idp="ras",
            HTTP_PROXY=HTTP_PROXY,
        )

    def get_auth_url(self):
        """
        Get authorization uri from discovery doc
        """
        authorization_endpoint = self.get_value_from_discovery_doc(
            "authorization_endpoint", ""
        )

        uri, state = self.session.create_authorization_url(
            authorization_endpoint, prompt="login"
        )

        return uri

    def get_userinfo(self, token):
        # As of now RAS does not provide their v1.1/userinfo in their .well-known/openid-configuration
        # Need to manually change version at the moment with config
        # TODO: Remove this once RAS makes it available in their openid-config
        issuer = self.get_value_from_discovery_doc("issuer", "")
        userinfo_endpoint = config["RAS_USERINFO_ENDPOINT"]
        userinfo_endpoint = issuer + userinfo_endpoint
        access_token = token["access_token"]
        header = {"Authorization": "Bearer " + access_token}
        res = requests.get(userinfo_endpoint, headers=header)
        if res.status_code != 200:
            msg = res.text
            try:
                msg = res.json()
            except Exception:
                pass
            self.logger.error(
                "Unable to get visa: status_code: {}, message: {}".format(
                    res.status_code,
                    msg,
                )
            )
            return {}
        return res.json()

    def get_encoded_visas_v11_userinfo(self, userinfo, pkey_cache=None):
        """
        Return encoded visas after extracting and validating passport from userinfo response

        Args:
            userinfo (dict): userinfo response
            pkey_cache (dict): app cache of public keys_dir

        Return:
            list: list of encoded GA4GH visas
        """
        encoded_passport = userinfo.get("passport_jwt_v11")
        return (
            fence.resources.ga4gh.passports.get_unvalidated_visas_from_valid_passport(
                encoded_passport, pkey_cache
            )
        )

    def get_user_id(self, code):

        err_msg = "Can't get user's info"

        try:
            token_endpoint = self.get_value_from_discovery_doc("token_endpoint", "")
            jwks_endpoint = self.get_value_from_discovery_doc("jwks_uri", "")

            token = self.get_token(token_endpoint, code)
            keys = self.get_jwt_keys(jwks_endpoint)
            userinfo = self.get_userinfo(token)

            claims = jose_jwt.decode(
                token["id_token"],
                keys,
                options={"verify_aud": False, "verify_at_hash": False},
            )

            # Log txn in access token for RAS ISA compliance
            at_claims = jose_jwt.decode(
                token["access_token"], keys, options={"verify_aud": False}
            )
            self.logger.info(
                "Received RAS access token with txn: {}".format(at_claims.get("txn"))
            )

            username = None
            if userinfo.get("UserID"):
                username = userinfo["UserID"]
                field_name = "UserID"
            elif userinfo.get("userid"):
                username = userinfo["userid"]
                field_name = "userid"
            elif userinfo.get("preferred_username"):
                username = userinfo["preferred_username"]
                field_name = "preferred_username"
            elif claims.get("sub"):
                username = claims["sub"]
                field_name = "sub"
            if not username:
                self.logger.error(
                    "{}, received claims: {} and userinfo: {}".format(
                        err_msg, claims, userinfo
                    )
                )
                return {"error": err_msg}

            self.logger.info("Using {} field as username.".format(field_name))

            email = userinfo.get("email")
            issuer = self.get_value_from_discovery_doc("issuer", "")
            subject_id = userinfo.get("sub")
            if not issuer or not subject_id:
                err_msg = "Could not determine both issuer and subject id"
                self.logger.error(err_msg)
                return {"error": err_msg}
            username = self.map_iss_sub_pair_to_user(
                issuer, subject_id, username, email
            )

            # Save userinfo and token in flask.g for later use in post_login
            flask.g.userinfo = userinfo
            flask.g.tokens = token
            flask.g.keys = keys

        except Exception as e:
            self.logger.exception("{}: {}".format(err_msg, e))
            return {"error": err_msg}

        return {"username": username, "email": email}

    def map_iss_sub_pair_to_user(self, issuer, subject_id, username, email):
        """
        Map <issuer, subject_id> combination to a Fence user whose username
        equals the username argument passed into this function.

        One exception to this is when two Fence users exist who both
        correspond to the user who is trying to log in. Please see logged
        warning for more details.

        Args:
            issuer (str): issuer
            subject_id (str): subject
            username (str): username of the Fence user who is being mapped to
            email (str): email to populate the mapped Fence user with in cases
                         when this function creates the mapped user or changes
                         its username

        Return:
            str: username that should be logged in. this will be equal to
                 username that was passed in in all cases except for the
                 exception noted above
        """
        with flask.current_app.db.session as db_session:
            iss_sub_pair_to_user = db_session.query(IssSubPairToUser).get(
                (issuer, subject_id)
            )
            user = query_for_user(db_session, username)
            if iss_sub_pair_to_user:
                if not user:
                    self.logger.info(
                        f'Issuer ("{issuer}") and subject id ("{subject_id}") '
                        "have already been mapped to a Fence user "
                        f'("{iss_sub_pair_to_user.user.username}") created '
                        "from the DRS endpoint. Changing said user's username"
                        f' to "{username}".'
                    )
                    # TODO also change username in Arborist
                    iss_sub_pair_to_user.user.username = username
                    iss_sub_pair_to_user.user.email = email
                    db_session.commit()
                elif iss_sub_pair_to_user.user.username != username:
                    self.logger.warning(
                        "Two users exist in the Fence database corresponding "
                        "to the user who is currently trying to log in: one "
                        f'created from an earlier login ("{username}") and '
                        f"one created from the DRS endpoint "
                        f'("{iss_sub_pair_to_user.user.username}"). '
                        f'"{iss_sub_pair_to_user.user.username}" will be '
                        f'logged in, rendering "{username}" inaccessible.'
                    )
                return iss_sub_pair_to_user.user.username

            if not user:
                user = create_user(
                    db_session,
                    self.logger,
                    username,
                    email=email,
                    idp_name=IdentityProvider.ras,
                )

            self.logger.info("Mapping issuer and subject id to Fence user")
            iss_sub_pair_to_user = IssSubPairToUser(iss=issuer, sub=subject_id)
            iss_sub_pair_to_user.user = user
            db_session.add(iss_sub_pair_to_user)
            db_session.commit()
            return iss_sub_pair_to_user.user.username

    @backoff.on_exception(backoff.expo, Exception, **DEFAULT_BACKOFF_SETTINGS)
    def update_user_visas(self, user, pkey_cache, db_session=current_session):
        """
        Updates user's RAS refresh token and uses the new access token to retrieve new visas from
        RAS's /userinfo endpoint and update the db with the new visa.
        - delete user's visas from db if we're not able to get a new access_token
        - delete user's visas from db if we're not able to get new visas
        - only visas which pass validation are added to the database
        """
        # Note: in the cronjob this is called per-user per-visa.
        # So it should be noted that when there are more clients than just RAS,
        # this code as it stands can remove visas that the user has from other clients.
        user.ga4gh_visas_v1 = []
        db_session.commit()

        try:
            token_endpoint = self.get_value_from_discovery_doc("token_endpoint", "")
            token = self.get_access_token(user, token_endpoint, db_session)
            userinfo = self.get_userinfo(token)
            encoded_visas = self.get_encoded_visas_v11_userinfo(userinfo, pkey_cache)
        except Exception as e:
            err_msg = "Could not retrieve visas"
            self.logger.exception("{}: {}".format(err_msg, e))
            raise

        for encoded_visa in encoded_visas:
            try:
                visa_issuer = get_iss(encoded_visa)
                visa_kid = get_kid(encoded_visa)
            except Exception as e:
                self.logger.error(
                    "Could not get issuer or kid from visa: {}. Discarding visa.".format(
                        e
                    )
                )
                continue  # Not raise: If visa malformed, does not make sense to retry

            # See if pkey is in cronjob cache; if not, update cache.
            public_key = pkey_cache.get(visa_issuer, {}).get(visa_kid)
            try:
                # Validate the visa per GA4GH AAI "Embedded access token" format rules.
                # pyjwt also validates signature and expiration.
                decoded_visa = validate_jwt(
                    encoded_token=encoded_visa,
                    public_key=public_key,
                    attempt_refresh=True,
                    # Embedded token must contain scope claim, which must include openid
                    scope={"openid"},
                    require_purpose=False,
                    issuers=config.get("GA4GH_VISA_ISSUER_ALLOWLIST", []),
                    # Embedded token must contain iss, sub, iat, exp claims
                    # options={"require": ["iss", "sub", "iat", "exp"]},
                    # ^ FIXME 2021-05-13: Above needs pyjwt>=v2.0.0, which requires cryptography>=3.
                    # Once we can unpin and upgrade cryptography and pyjwt, switch to above "options" arg.
                    # For now, pyjwt 1.7.1 is able to require iat and exp;
                    # authutils' validate_jwt (i.e. the function being called) checks issuers already (see above);
                    # and we will check separately for sub below.
                    pkey_cache=pkey_cache,
                    options={
                        "require_iat": True,
                        "require_exp": True,
                        "verify_aud": False,
                    },
                )

                # Also require 'sub' claim (see note above about pyjwt and the options arg).
                if "sub" not in decoded_visa:
                    raise JWTError("Visa is missing the 'sub' claim.")
                # Embedded token must not contain aud claim
                if "aud" in decoded_visa:
                    raise JWTError("Visa contains 'aud' calim")
            except Exception as e:
                self.logger.error(
                    "Visa failed validation: {}. Discarding visa.".format(e)
                )
                continue

            visa = GA4GHVisaV1(
                user=user,
                source=decoded_visa["ga4gh_visa_v1"]["source"],
                type=decoded_visa["ga4gh_visa_v1"]["type"],
                asserted=int(decoded_visa["ga4gh_visa_v1"]["asserted"]),
                expires=int(decoded_visa["exp"]),
                ga4gh_visa=encoded_visa,
            )

            current_db_session = db_session.object_session(visa)
            current_db_session.add(visa)
            db_session.commit()
