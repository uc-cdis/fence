import flask
import collections
import time
import datetime
import gen3authz.client.arborist.client

# TODO comment regarding circular imports
import fence.scripting.fence_create

# TODO take this out
import jwt

from flask_sqlalchemy_session import current_session
from cdislogging import get_logger

from fence.jwt.validate import validate_jwt
from fence.config import config
from fence.models import query_for_user, GA4GHVisaV1, User
from fence.sync.passport_sync.ras_sync import RASVisa

logger = get_logger(__name__)


def get_gen3_users_from_ga4gh_passports(passports):
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
            raw_visas = get_unvalidated_visas_from_valid_passport(passport)
        except Exception as exc:
            logger.warning(f"invalid passport provided, ignoring. Error: {exc}")
            continue

        identity_to_visas = collections.defaultdict(list)
        min_visa_expiration = int(time.time()) + datetime.timedelta(hours=1).seconds
        for raw_visa in raw_visas:
            try:
                # TODO must be signed with RSA256
                # TODO issuers could be more than just what's below. will need to use config var of some sort
                # TODO why is subject_id a big long str?
                # TODO conditions field
                # issuers = ["https://stsstg.nih.gov"]
                # decoded_visa = validate_jwt(raw_visa, attempt_refresh=True, issuers=issuers, options={"verify_aud": False})
                # TODO: ONLY USE THIS FOR DEVELOPMENT
                decoded_visa = jwt.decode(raw_visa, verify=False)
                identity_to_visas[
                    (decoded_visa.get("iss"), decoded_visa.get("sub"))
                ].append((raw_visa, decoded_visa))
                min_visa_expiration = min(min_visa_expiration, decoded_visa.get("exp"))
                # min_visa_expiration = decoded_visa.

                # below function also validates visa (or raises exception) and
                # extracts the subject id
                # subject_id, issuer = get_sub_iss_from_visa(raw_visa)

                # query idp user table
                # gen3_user = get_or_create_gen3_user_from_sub_iss(decoded_visa.get("sub"), decoded_visa.get("iss"))
                # user_ids_from_passports.append(gen3_user.id)

            except Exception as exc:
                logger.warning(f"invalid visa provided, ignoring. Error: {exc}")
                continue

        usernames_from_current_passport = []
        for (issuer, subject_id), visas in identity_to_visas.items():
            gen3_user = get_or_create_gen3_user_from_iss_sub(issuer, subject_id)
            # NOTE: does not validate, assumes validation occurs above.
            # sync_visa_authorization(raw_visa)

            # QUESTION: do all visas in a passport necessarily belong
            # to the same Arborist defined user? relevant because you can only
            # update policies in Arborist one user at a time
            ga4gh_visas = [
                GA4GHVisaV1(
                    user=gen3_user,
                    source=decoded_visa["ga4gh_visa_v1"]["source"],
                    type=decoded_visa["ga4gh_visa_v1"]["type"],
                    asserted=int(decoded_visa["ga4gh_visa_v1"]["asserted"]),
                    expires=int(decoded_visa["exp"]),
                    ga4gh_visa=raw_visa,
                )
                for raw_visa, decoded_visa in visas
            ]
            sync_visa_authorization(gen3_user, ga4gh_visas, min_visa_expiration)
            usernames_from_current_passport.append(gen3_user.username)

        put_gen3_usernames_for_passport_into_cache(
            passport, usernames_from_current_passport
        )

    return list(set(usernames_from_all_passports))


def get_gen3_usernames_for_passport_from_cache(passport):
    cached_user_ids = []
    # TODO
    return cached_user_ids


def get_unvalidated_visas_from_valid_passport(passport):
    # validate passport, return visas
    # TODO put inside try block (i.e. shouldn't get a 500 for an expired passport)
    # TODO if aud is provided, it must contain client id
    # TODO dont hardcode issuers. it needed to be hardcoded because I think
    # TODO init issuers list within function call
    # list of allowed issuers comes from a config variable

    # issuers = ["https://stsstg.nih.gov"]
    # decoded_passport = validate_jwt(passport, attempt_refresh=True, issuers=issuers, options={"verify_aud": False})
    # TODO: ONLY USE THIS FOR DEVELOPMENT
    decoded_passport = jwt.decode(passport, verify=False)

    return decoded_passport.get("ga4gh_passport_v1", [])


def is_raw_visa_valid(raw_visa):
    # check signature
    # is a type we recognize?
    return False


def get_sub_iss_from_visa(raw_visa):
    if not is_raw_visa_valid(raw_visa):
        raise Exception()

    subject_id = None
    issuer = None

    # TODO

    return subject_id, issuer


def get_or_create_gen3_user_from_iss_sub(issuer, subject_id):
    # for idp_name, idp_config in config.get("OPENID_CONNECT", {}).items():

    # there are issues with syncing when "https://" is part of the username.
    # for example,  Arborist returns a 301 for a `POST /user/
    # {username}/policy` request, possibly due to the slashes.
    # TODO may want to use urllib to get rid of protocol
    issuer = issuer.replace("https://", "")
    username = issuer + "_" + subject_id
    with flask.current_app.db.session as db_session:
        user = query_for_user(db_session, username)
        if not user:
            user = User(username=username)
            db_session.add(user)
            db_session.commit()
    return user


def sync_visa_authorization(gen3_user, ga4gh_visas, expiration):
    # TODO might need to look in more places for db_url
    db_url = config.get("DB")
    arborist_client = gen3authz.client.arborist.client.ArboristClient(
        arborist_base_url=config.get("ARBORIST"), logger=logger, authz_provider="GA4GH"
    )
    # TODO check this
    dbgap_config = config.get("dbGaP")
    syncer = fence.scripting.fence_create.init_syncer(
        dbgap_config, None, db_url, arborist=arborist_client
    )

    syncer.sync_single_user_visas(
        gen3_user, ga4gh_visas, current_session, expiration=expiration
    )


def put_gen3_usernames_for_passport_into_cache(passport, usernames_from_passports):
    pass
