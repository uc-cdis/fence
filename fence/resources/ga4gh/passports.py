from sqlalchemy import text
import flask
import os
import collections
import hashlib
import time
import datetime
import jwt

# the whole fence_create module is imported to avoid issue with circular imports
import fence.scripting.fence_create

from authutils.errors import JWTError
from authutils.token.core import get_iss, get_kid
from cdislogging import get_logger
from flask import current_app

from fence.jwt.validate import validate_jwt
from fence.config import config
from fence.models import (
    create_user,
    query_for_user,
    query_for_user_by_id,
    GA4GHVisaV1,
    GA4GHPassportCache,
    IdentityProvider,
    IssSubPairToUser,
)

logger = get_logger(__name__)

# cache will be in following format
#   passport_hash: ([user_id_0, user_id_1, ...], expires_at)
PASSPORT_CACHE = {}


def sync_gen3_users_authz_from_ga4gh_passports(
    passports, pkey_cache=None, db_session=None, skip_google_updates=False
):
    """
    Validate passports and embedded visas, using each valid visa's identity
    established by <iss, sub> combination to possibly create and definitely
    determine a Fence user who is added to the list returned by this
    function. In the process of determining Fence users from visas, visa
    authorization information is also persisted in Fence and synced to
    Arborist.

    Args:
        passports (list): a list of raw encoded passport strings, each
                          including header, payload, and signature
        skip_google_updates (bool): True if google group updates should be skipped. False if otherwise.

    Return:
        list: a list of users, each corresponding to a valid visa identity
              embedded within the passports passed in
    """
    db_session = db_session or current_app.scoped_session()

    # {"username": user, "username2": user2}
    users_from_all_passports = {}
    for passport in passports:
        try:
            cached_usernames = get_gen3_usernames_for_passport_from_cache(
                passport=passport, db_session=db_session
            )
            if cached_usernames:
                # there's a chance a given username exists in the cache but no longer in
                # the database. if not all are in db, ignore the cache and actually parse
                # and validate the passport
                all_users_exist_in_db = True
                usernames_to_update = {}
                for username in cached_usernames:
                    user = query_for_user(session=db_session, username=username)
                    if not user:
                        all_users_exist_in_db = False
                        continue
                    usernames_to_update[user.username] = user

                if all_users_exist_in_db:
                    users_from_all_passports.update(usernames_to_update)
                    # existence in the cache and a user in db means that this passport
                    # was validated previously (expiration was also checked)
                    continue

            # below function also validates passport (or raises exception)
            raw_visas = get_unvalidated_visas_from_valid_passport(
                passport, pkey_cache=pkey_cache
            )
        except Exception as exc:
            logger.warning(f"Invalid passport provided, ignoring. Error: {exc}")
            continue

        # an empty raw_visas list means that either the current passport is
        # invalid or that it has no visas. in both cases, the current passport
        # is ignored and we move on to the next passport
        if not raw_visas:
            continue

        identity_to_visas = collections.defaultdict(list)
        min_visa_expiration = int(time.time()) + datetime.timedelta(hours=1).seconds
        for raw_visa in raw_visas:
            try:
                validated_decoded_visa = validate_visa(raw_visa, pkey_cache=pkey_cache)
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
                logger.warning(f"Invalid visa provided, ignoring. Error: {exc}")
                continue

        expired_authz_removal_job_freq_in_seconds = config[
            "EXPIRED_AUTHZ_REMOVAL_JOB_FREQ_IN_SECONDS"
        ]
        min_visa_expiration -= expired_authz_removal_job_freq_in_seconds
        if min_visa_expiration <= int(time.time()):
            logger.warning(
                "The passport's earliest valid visa expiration time is set to "
                f"occur within {expired_authz_removal_job_freq_in_seconds} "
                "seconds from now, which is too soon an expiration to handle."
            )
            continue

        users_from_current_passport = []
        for (issuer, subject_id), visas in identity_to_visas.items():
            gen3_user = get_or_create_gen3_user_from_iss_sub(
                issuer, subject_id, db_session=db_session
            )

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
            #       This adds the visas to the database session but doesn't commit until
            #       the end of this function
            _sync_validated_visa_authorization(
                gen3_user=gen3_user,
                ga4gh_visas=ga4gh_visas,
                expiration=min_visa_expiration,
                db_session=db_session,
                skip_google_updates=skip_google_updates,
            )
            users_from_current_passport.append(gen3_user)

        for user in users_from_current_passport:
            users_from_all_passports[user.username] = user

        put_gen3_usernames_for_passport_into_cache(
            passport=passport,
            user_ids_from_passports=list(users_from_all_passports.keys()),
            expires_at=min_visa_expiration,
            db_session=db_session,
        )

    db_session.commit()

    logger.info(
        f"Got Gen3 usernames from passport(s): {list(users_from_all_passports.keys())}"
    )
    return users_from_all_passports


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
            raise JWTError(f"Passport is missing the 'sub' claim")
    except Exception as e:
        logger.error("Passport failed validation: {}. Discarding passport.".format(e))
        # ignore malformed/invalid passports
        return []

    return decoded_passport.get("ga4gh_passport_v1", [])


def validate_visa(raw_visa, pkey_cache=None):
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
    if jwt.get_unverified_header(raw_visa).get("jku"):
        raise Exception(
            "Visa Document Tokens are not currently supported by passing "
            '"jku" in the header. Only Visa Access Tokens are supported.'
        )

    logger.info("Attempting to validate visa")

    decoded_visa = validate_jwt(
        raw_visa,
        attempt_refresh=True,
        scope={"openid", "ga4gh_passport_v1"},
        require_purpose=False,
        issuers=config["GA4GH_VISA_ISSUER_ALLOWLIST"],
        options={"require_iat": True, "require_exp": True, "verify_aud": False},
        pkey_cache=pkey_cache,
    )
    logger.info(f'Visa jti: "{decoded_visa.get("jti", "")}"')
    logger.info(f'Visa txn: "{decoded_visa.get("txn", "")}"')

    for claim in ["sub", "ga4gh_visa_v1"]:
        if claim not in decoded_visa:
            raise Exception(f'Visa does not contain REQUIRED "{claim}" claim')

    if "aud" in decoded_visa:
        raise Exception('Visa MUST NOT contain "aud" claim')

    field_to_allowed_values = config["GA4GH_VISA_V1_CLAIM_REQUIRED_FIELDS"]
    for field, allowed_values in field_to_allowed_values.items():
        if field not in decoded_visa["ga4gh_visa_v1"]:
            raise Exception(
                f'"ga4gh_visa_v1" claim does not contain REQUIRED "{field}" field'
            )
        if decoded_visa["ga4gh_visa_v1"][field] not in allowed_values:
            raise Exception(
                f'{field}={decoded_visa["ga4gh_visa_v1"][field]} field in "ga4gh_visa_v1" is not equal to one of the allowed_values: {allowed_values}'
            )

    if "asserted" not in decoded_visa["ga4gh_visa_v1"]:
        raise Exception(
            '"ga4gh_visa_v1" claim does not contain REQUIRED "asserted" field'
        )
    asserted = decoded_visa["ga4gh_visa_v1"]["asserted"]
    if type(asserted) not in (int, float):
        raise Exception(
            '"ga4gh_visa_v1" claim object\'s "asserted" field\'s type is not '
            "JSON numeric"
        )
    if decoded_visa["iat"] < asserted:
        raise Exception(
            "The Passport Visa Assertion Source made the claim after the visa "
            'was minted (i.e. "ga4gh_visa_v1" claim object\'s "asserted" '
            'field is greater than the visa\'s "iat" claim)'
        )

    if "conditions" in decoded_visa["ga4gh_visa_v1"]:
        logger.warning(
            'Condition checking is not yet supported, but a visa was received that contained the "conditions" field'
        )
        if decoded_visa["ga4gh_visa_v1"]["conditions"]:
            raise Exception('"conditions" field in "ga4gh_visa_v1" is not empty')

    logger.info("Visa was successfully validated")
    return decoded_visa


def get_or_create_gen3_user_from_iss_sub(issuer, subject_id, db_session=None):
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
    db_session = db_session or current_app.scoped_session()
    logger.debug(
        f"get_or_create_gen3_user_from_iss_sub: issuer: {issuer} & subject_id: {subject_id}"
    )
    iss_sub_pair_to_user = db_session.get(IssSubPairToUser, (issuer, subject_id))
    if not iss_sub_pair_to_user:
        username = subject_id + issuer[len("https://") :]
        gen3_user = query_for_user(session=db_session, username=username)
        idp_name = IssSubPairToUser.ISSUER_TO_IDP.get(issuer)
        logger.debug(f"issuer_to_idp: {IssSubPairToUser.ISSUER_TO_IDP}")
        if not gen3_user:
            gen3_user = create_user(db_session, logger, username, idp_name=idp_name)
            if not idp_name:
                logger.info(
                    f"The user (id:{gen3_user.id}) was created without a linked identity "
                    f"provider since it could not be determined based on "
                    f"the issuer {issuer}"
                )

        # ensure user has an associated identity provider
        if not gen3_user.identity_provider:
            idp = (
                db_session.query(IdentityProvider)
                .filter(IdentityProvider.name == idp_name)
                .first()
            )
            if not idp:
                idp = IdentityProvider(name=idp_name)
            gen3_user.identity_provider = idp

        logger.info(
            f'Mapping subject id ("{subject_id}") and issuer '
            f'("{issuer}") combination to Fence user '
            f'"{gen3_user.username}" with IdP = "{idp_name}"'
        )
        iss_sub_pair_to_user = IssSubPairToUser(iss=issuer, sub=subject_id)
        iss_sub_pair_to_user.user = gen3_user

        db_session.add(iss_sub_pair_to_user)
        db_session.commit()

    return iss_sub_pair_to_user.user


def _sync_validated_visa_authorization(
    gen3_user, ga4gh_visas, expiration, db_session=None, skip_google_updates=False
):
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
                            that are parsed
        expiration (int): time at which synced Arborist policies and
                          inclusion in any GBAG are set to expire
        skip_google_updates (bool): True if google group updates should be skipped. False if otherwise.
    Return:
        None
    """
    db_session = db_session or current_app.scoped_session()
    default_args = fence.scripting.fence_create.get_default_init_syncer_inputs(
        authz_provider="GA4GH"
    )
    syncer = fence.scripting.fence_create.init_syncer(**default_args)

    synced_visas = syncer.sync_single_user_visas(
        gen3_user,
        ga4gh_visas,
        db_session,
        expires=expiration,
        skip_google_updates=skip_google_updates,
    )

    # after syncing authorization, persist the visas that were parsed successfully.
    for visa in ga4gh_visas:
        if visa not in synced_visas:
            logger.debug(f"deleting visa with id={visa.id} from db session")
            db_session.delete(visa)
        else:
            logger.debug(f"adding visa with id={visa.id} to db session")
            db_session.add(visa)


def get_gen3_usernames_for_passport_from_cache(passport, db_session=None):
    """
    Attempt to retrieve a cached list of users ids for a previously validated and
    non-expired passport.

    Args:
        passport (str): ga4gh encoded passport JWT
        db_session (None, sqlalchemy session): optional database session to use

    Returns:
        list[str]: list of usernames for users referred to by the previously validated
                   and non-expired passport
    """
    db_session = db_session or current_app.scoped_session()
    user_ids_from_passports = None
    current_time = int(time.time())

    passport_hash = hashlib.sha256(passport.encode("utf-8")).hexdigest()

    # try to retrieve from local in-memory cache
    if passport_hash in PASSPORT_CACHE:
        user_ids_from_passports, expires = PASSPORT_CACHE[passport_hash]
        if expires > current_time:
            logger.debug(
                f"Got users {user_ids_from_passports} for provided passport from in-memory cache. "
                f"Expires: {expires}, Current Time: {current_time}"
            )
            return user_ids_from_passports
        else:
            # expired, so remove it
            del PASSPORT_CACHE[passport_hash]

    # try to retrieve from database cache
    cached_passport = (
        db_session.query(GA4GHPassportCache)
        .filter(GA4GHPassportCache.passport_hash == passport_hash)
        .first()
    )
    if cached_passport:
        if cached_passport.expires_at > current_time:
            user_ids_from_passports = cached_passport.user_ids

            # update local cache
            PASSPORT_CACHE[passport_hash] = (
                user_ids_from_passports,
                cached_passport.expires_at,
            )

            logger.debug(
                f"Got users {user_ids_from_passports} for provided passport from "
                f"database cache and placed in in-memory cache. "
                f"Expires: {cached_passport.expires_at}, Current Time: {current_time}"
            )
            return user_ids_from_passports
        else:
            # expired, so delete it
            db_session.delete(cached_passport)
            db_session.commit()

    return user_ids_from_passports


def put_gen3_usernames_for_passport_into_cache(
    passport, user_ids_from_passports, expires_at, db_session=None
):
    """
    Cache a validated and non-expired passport and map to the user_ids referenced
    by the content.

    Args:
        passport (str): ga4gh encoded passport JWT
        db_session (None, sqlalchemy session): optional database session to use
        user_ids_from_passports (list[str]): list of user identifiers referred to by
            the previously validated and non-expired passport
        expires_at (int): expiration time in unix time
    """
    db_session = db_session or current_app.scoped_session()

    passport_hash = hashlib.sha256(passport.encode("utf-8")).hexdigest()

    # stores back to cache and db
    PASSPORT_CACHE[passport_hash] = user_ids_from_passports, expires_at

    db_session.execute(
        text(
            """\
        INSERT INTO ga4gh_passport_cache (
            passport_hash,
            expires_at,
            user_ids
        ) VALUES (
            :passport_hash,
            :expires_at,
            :user_ids
        ) ON CONFLICT (passport_hash) DO UPDATE SET
            expires_at = EXCLUDED.expires_at,
            user_ids = EXCLUDED.user_ids;"""
        ),
        dict(
            passport_hash=passport_hash,
            expires_at=expires_at,
            user_ids=user_ids_from_passports,
        ),
    )

    logger.debug(
        f"Cached {user_ids_from_passports} passport in "
        f"database. "
        f"Expires: {expires_at}"
    )


# TODO to be called after login
def map_gen3_iss_sub_pair_to_user(gen3_issuer, gen3_subject_id, gen3_user):
    pass
