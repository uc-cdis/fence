import flask
import os
import collections
import time
import datetime

# the whole fence_create module is imported to avoid issue with circular imports
import fence.scripting.fence_create

from authutils.errors import JWTError
from authutils.token.core import get_iss, get_kid
from cdislogging import get_logger
from gen3authz.client.arborist.client import ArboristClient

from fence.jwt.validate import validate_jwt
from fence.config import config
from fence.models import (
    query_for_user,
    GA4GHVisaV1,
    User,
    IdentityProvider,
    IssSubPairToUser,
)

logger = get_logger(__name__)


def sync_gen3_users_authz_from_ga4gh_passports(passports, pkey_cache=None):
    """
    Validate passports and embedded visas, using each valid visa's identity
    established by <iss, sub> combination to possibly create and definitely
    determine a Fence user whose username is added to the list returned by
    this function. In the process of determining Fence users from visas, visa
    authorization information is also persisted in Fence and synced to
    Arborist.

    Args:
        passports (list): a list of raw encoded passport strings, each
                          including header, payload, and signature

    Return:
        list: a list of strings, each being the username of a Fence user who
              corresponds to a valid visa identity embedded within the passports
              passed in.
    """
    logger.info("getting gen3 users from passports")
    usernames_from_all_passports = []
    for passport in passports:
        try:
            # TODO check cache
            cached_usernames = get_gen3_usernames_for_passport_from_cache(passport)
            if cached_usernames:
                usernames_from_all_passports.extend(cached_usernames)
                # existence in the cache means that this passport was validated
                # previously
                continue

            # below function also validates passport (or raises exception)
            raw_visas = get_unvalidated_visas_from_valid_passport(
                passport, pkey_cache=pkey_cache
            )
        except Exception as exc:
            logger.warning(f"invalid passport provided, ignoring. Error: {exc}")
            continue

        if not raw_visas:
            continue

        identity_to_visas = collections.defaultdict(list)
        min_visa_expiration = int(time.time()) + datetime.timedelta(hours=1).seconds
        for raw_visa in raw_visas:
            try:
                validated_decoded_visa = validate_visa(raw_visa)
                identity_to_visas[
                    (
                        validated_decoded_visa.get("iss"),
                        validated_decoded_visa.get("sub"),
                    )
                ].append((raw_visa, validated_decoded_visa))
                min_visa_expiration = min(
                    min_visa_expiration, validated_decoded_visa.get("exp")
                )
            except Exception as exc:
                logger.warning(f"invalid visa provided, ignoring. Error: {exc}")
                continue

        delete_expired_google_access_job_frequency = config.get(
            "DELETE_EXPIRED_GOOGLE_ACCESS_JOB_FREQUENCY_IN_SECONDS", 300
        )
        min_visa_expiration -= delete_expired_google_access_job_frequency
        if min_visa_expiration <= int(time.time()):
            logger.warning(
                "the passport's minimum visa expiration time fell within "
                f"{delete_expired_google_access_job_frequency} seconds of now, "
                "which is the frequency of the delete_expired_google_access job. "
                "for this reason, the passport will be ignored"
            )
            continue

        usernames_from_current_passport = []
        for (issuer, subject_id), visas in identity_to_visas.items():
            gen3_user = get_or_create_gen3_user_from_iss_sub(issuer, subject_id)

            ga4gh_visas = [
                GA4GHVisaV1(
                    user=gen3_user,
                    source=validated_decoded_visa["ga4gh_visa_v1"]["source"],
                    type=validated_decoded_visa["ga4gh_visa_v1"]["type"],
                    asserted=int(validated_decoded_visa["ga4gh_visa_v1"]["asserted"]),
                    expires=int(validated_decoded_visa["exp"]),
                    ga4gh_visa=raw_visa,
                )
                for raw_visa, validated_decoded_visa in visas
            ]
            # NOTE: does not validate, assumes validation occurs above.
            sync_validated_visa_authorization(
                gen3_user, ga4gh_visas, min_visa_expiration
            )
            usernames_from_current_passport.append(gen3_user.username)

        put_gen3_usernames_for_passport_into_cache(
            passport, usernames_from_current_passport
        )
        usernames_from_all_passports.extend(usernames_from_current_passport)

    return list(set(usernames_from_all_passports))


def get_gen3_usernames_for_passport_from_cache(passport):
    cached_user_ids = []
    # TODO
    return cached_user_ids


def get_unvalidated_visas_from_valid_passport(passport, pkey_cache=None):
    """
    Return encoded visas after extracting and validating encoded passport

    Args:
        passport (string): encoded ga4gh passport
        pkey_cache (dict): app cache of public keys_dir

    Return:
        list: list of encoded GA4GH visas
    """
    decoded_passport = {}
    passport_issuer, passport_kid = None, None

    if not pkey_cache:
        pkey_cache = {}

    try:
        passport_issuer = get_iss(passport)
        passport_kid = get_kid(passport)
    except Exception as e:
        logger.error(
            "Could not get issuer or kid from passport: {}. Discarding passport.".format(
                e
            )
        )
        # ignore malformed/invalid passports
        return []

    public_key = pkey_cache.get(passport_issuer, {}).get(passport_kid)

    try:
        decoded_passport = validate_jwt(
            encoded_token=passport,
            public_key=public_key,
            attempt_refresh=True,
            require_purpose=False,
            scope={"openid"},
            issuers=config.get("GA4GH_VISA_ISSUER_ALLOWLIST", []),
            options={
                "require_iat": True,
                "require_exp": True,
                "verify_aud": False,
            },
        )

        if "sub" not in decoded_passport:
            raise JWTError("Visa is missing the 'sub' claim.")
    except Exception as e:
        logger.error("Passport failed validation: {}. Discarding passport.".format(e))
        # ignore malformed/invalid passports
        return []

    return decoded_passport.get("ga4gh_passport_v1", [])


def validate_visa(raw_visa):
    """
    Validate a raw visa in accordance with:
        - GA4GH AAI spec (https://github.com/ga4gh/data-security/blob/master/AAI/AAIConnectProfile.md)
        - GA4GH DURI spec (https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md)

    Args:
        raw_visa (str): a raw, encoded visa including header, payload, and signature

    Return:
        dict: the decoded payload if validation was successful. an exception
              is raised if validation was unsuccessful
    """
    # TODO check that there is no JKU field in header?
    decoded_visa = validate_jwt(
        raw_visa,
        attempt_refresh=True,
        scope={"openid", "ga4gh_passport_v1"},
        require_purpose=False,
        issuers=config.get("GA4GH_VISA_ISSUER_ALLOWLIST", []),
        options={"require_iat": True, "require_exp": True, "verify_aud": False},
    )
    # TODO log jti?
    # TODO log txn?
    for claim in ["sub", "ga4gh_visa_v1"]:
        if claim not in decoded_visa:
            raise Exception(f'Visa does not contain REQUIRED "{claim}" claim')

    if "aud" in decoded_visa:
        raise Exception('Visa MUST NOT contain "aud" claim')

    field_to_expected_value = config.get("GA4GH_VISA_V1_CLAIM_REQUIRED_FIELDS")
    for field, expected_value in field_to_expected_value.items():
        if field not in decoded_visa["ga4gh_visa_v1"]:
            raise Exception(
                f'"ga4gh_visa_v1" claim does not contain REQUIRED "{field}" field'
            )
        if expected_value:
            if decoded_visa["ga4gh_visa_v1"][field] != expected_value:
                raise Exception(
                    f'"{field}" field in "ga4gh_visa_v1" does not equal expected value "{expected_value}"'
                )

    if "conditions" in decoded_visa["ga4gh_visa_v1"]:
        logger.warning(
            'condition checking is not yet supported, but a visa was received that contained the "conditions" field'
        )
        if decoded_visa["ga4gh_visa_v1"]["conditions"]:
            raise Exception('"conditions" field in "ga4gh_visa_v1" is not empty')

    logger.info("visa was successfully validated")
    return decoded_visa


def get_or_create_gen3_user_from_iss_sub(issuer, subject_id):
    """
    Get a user from the Fence database corresponding to the visa identity
    indicated by the <issuer, subject_id> combination. If a Fence user has
    not yet been created for the given <issuer, subject_id> combination,
    create and return such a user.

    Args:
        issuer (str): the issuer of a given visa
        subject_id (str): the subject of a given visa

    Return:
        userdatamodel.user.User: the Fence user corresponding to issuer and subject_id
    """
    with flask.current_app.db.session as db_session:
        iss_sub_pair_to_user = db_session.query(IssSubPairToUser).get(
            (issuer, subject_id)
        )
        if not iss_sub_pair_to_user:
            logger.info(
                "creating a new Fence user with a username formed from subject "
                "id and issuer. mapping subject id and issuer combination to "
                "said user"
            )
            username = subject_id + issuer[len("https://") :]
            gen3_user = User(username=username)
            idp_name = flask.current_app.issuer_to_idp.get(issuer)
            if idp_name:
                idp = (
                    db_session.query(IdentityProvider)
                    .filter(IdentityProvider.name == idp_name)
                    .first()
                )
                if not idp:
                    idp = IdentityProvider(name=idp_name)
                gen3_user.identity_provider = idp

            iss_sub_pair_to_user = IssSubPairToUser(iss=issuer, sub=subject_id)
            iss_sub_pair_to_user.user = gen3_user

            db_session.add(gen3_user)
            db_session.add(iss_sub_pair_to_user)
            db_session.commit()

        return iss_sub_pair_to_user.user


def sync_validated_visa_authorization(gen3_user, ga4gh_visas, expiration):
    """
    Wrapper around UserSyncer.sync_single_user_visas method, which parses
    authorization information from the provided visas, persists it in Fence,
    and syncs it to Arborist.

    IMPORTANT NOTE: THIS DOES NOT VALIDATE THE VISAS. ENSURE THIS IS DONE
                    BEFORE THIS.

    Args:
        gen3_user (userdatamodel.user.User): the Fence user whose visas'
                                             authz info is being synced
        ga4gh_visas (list): a list of fence.models.GA4GHVisaV1 objects
                            that are parsed and synced
        expiration (int): time at which synced Arborist policies and
                          inclusion in any GBAG are set to expire

    Return:
        None
    """
    default_args = fence.scripting.fence_create.get_default_init_syncer_inputs()
    syncer = fence.scripting.fence_create.init_syncer(
        STORAGE_CREDENTIALS=None, **default_args
    )

    with flask.current_app.db.session as db_session:
        synced_visas = syncer.sync_single_user_visas(
            gen3_user, ga4gh_visas, db_session, expires=expiration
        )

        # after syncing authorization, perist the visas that were parsed successfully
        for visa in synced_visas:
            db_session.add(visa)
        db_session.commit()


def put_gen3_usernames_for_passport_into_cache(passport, usernames_from_passports):
    pass
