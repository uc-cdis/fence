import backoff
import flask
import copy
import requests

# the whole passports module is imported to avoid issue with circular imports
import fence.resources.ga4gh.passports
import fence.scripting.fence_create
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

    def get_encoded_passport_v11_userinfo(self, userinfo):
        """
        Return encoded passport after extracting from userinfo response

        Args:
            userinfo (dict): userinfo response

        Return:
            str: encoded ga4gh passport
        """
        return userinfo.get("passport_jwt_v11")

    def get_encoded_visas_v11_userinfo(self, userinfo, pkey_cache=None):
        """
        Return encoded visas after extracting and validating passport from userinfo response

        Args:
            userinfo (dict): userinfo response
            pkey_cache (dict): app cache of public keys_dir

        Return:
            list: list of encoded GA4GH visas
        """
        encoded_passport = self.get_encoded_passport_v11_userinfo(userinfo)
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
            issuer (str): RAS issuer
            subject_id (str): RAS subject
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
                        "Issuer and subject id have already been mapped to a "
                        "Fence user created from the DRS/data endpoints. "
                        "Changing said user's username to the username "
                        "returned from the RAS userinfo endpoint."
                    )
                    # TODO also change username in Arborist
                    iss_sub_pair_to_user.user.username = username
                    iss_sub_pair_to_user.user.email = email
                    db_session.commit()
                elif iss_sub_pair_to_user.user.username != username:
                    self.logger.warning(
                        "Two users exist in the Fence database corresponding "
                        "to the RAS user who is currently trying to log in: one "
                        "created from an earlier login and one created from "
                        "the DRS/data endpoints. The one created from the "
                        "DRS/data endpoints will be logged in, rendering the "
                        "other one inaccessible."
                    )
                return iss_sub_pair_to_user.user.username

            if not user:
                self.logger.info(
                    "Creating a user in the Fence database before mapping issuer and subject id"
                )
                user = User(username=username, email=email)
                idp = (
                    db_session.query(IdentityProvider)
                    .filter(IdentityProvider.name == IdentityProvider.ras)
                    .first()
                )
                if not idp:
                    idp = IdentityProvider(name=IdentityProvider.ras)
                user.identity_provider = idp
                db_session.add(user)

            self.logger.info("Mapping issuer and subject id to Fence user")
            iss_sub_pair_to_user = IssSubPairToUser(iss=issuer, sub=subject_id)
            iss_sub_pair_to_user.user = user
            db_session.add(iss_sub_pair_to_user)
            db_session.commit()
            return iss_sub_pair_to_user.user.username

    @backoff.on_exception(backoff.expo, Exception, **DEFAULT_BACKOFF_SETTINGS)
    def update_user_authorization(self, user, pkey_cache, db_session=current_session):
        """
        Updates user's RAS refresh token and uses the new access token to retrieve new visas from
        RAS's /userinfo endpoint and update access
        """
        try:
            token_endpoint = self.get_value_from_discovery_doc("token_endpoint", "")
            token = self.get_access_token(user, token_endpoint, db_session)
            userinfo = self.get_userinfo(token)
            passport = self.get_encoded_passport_v11_userinfo(userinfo)
        except Exception as e:
            err_msg = "Could not retrieve visas"
            self.logger.exception("{}: {}".format(err_msg, e))
            raise

        # now sync authz updates
        user_ids_from_passports = (
            fence.resources.ga4gh.passports.sync_gen3_users_authz_from_ga4gh_passports(
                [passport], pkey_cache=pkey_cache
            )
        )

        # TODO?
        # put_gen3_usernames_for_passport_into_cache(
        #     passport, usernames_from_current_passport
        # )
