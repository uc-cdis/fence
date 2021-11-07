import flask
import os
import collections
import time
import datetime

# the whole fence_create module is imported to avoid issue with circular imports
import fence.scripting.fence_create

from gen3authz.client.arborist.client import ArboristClient
from cdislogging import get_logger

from fence.jwt.validate import validate_jwt
from fence.config import config
from fence.models import (
    query_for_user,
    GA4GHVisaV1,
    User,
    IdentityProvider,
    IssSubPairToUser,
)
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
        # TODO need to subtract 5 minutes
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
    return []


def validate_visa(raw_visa):
    # TODO check that there is no JKU field in header?
    decoded_visa = validate_jwt(
        raw_visa,
        attempt_refresh=True,
        scope={"openid", "ga4gh_passport_v1"},
        require_purpose=False,
        issuers=config.get("GA4GH_VISA_ISSUER_ALLOWLIST", []),
        options={"require_iat": True, "require_exp": True, "verify_aud": False},
    )
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
            'Condition checking is not yet supported, but a visa was received that contained the "conditions" field'
        )
        if decoded_visa["ga4gh_visa_v1"]["conditions"]:
            raise Exception('"conditions" field in "ga4gh_visa_v1" is not empty')

    return decoded_visa


def get_or_create_gen3_user_from_iss_sub(issuer, subject_id):
    with flask.current_app.db.session as db_session:
        iss_sub_pair_to_user = db_session.query(IssSubPairToUser).get(
            (issuer, subject_id)
        )
        if not (iss_sub_pair_to_user and iss_sub_pair_to_user.user):
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


def sync_visa_authorization(gen3_user, ga4gh_visas, expiration):
    arborist_client = ArboristClient(
        arborist_base_url=config.get("ARBORIST"), logger=logger, authz_provider="GA4GH"
    )

    dbgap_config = os.environ.get("dbGaP") or config.get("dbGaP")
    if not isinstance(dbgap_config, list):
        dbgap_config = [dbgap_config]
    DB = os.environ.get("FENCE_DB") or config.get("DB")
    if DB is None:
        try:
            from fence.settings import DB
        except ImportError:
            pass
    syncer = fence.scripting.fence_create.init_syncer(
        dbgap_config, None, DB, arborist=arborist_client
    )

    with flask.current_app.db.session as db_session:
        # TODO set expiration for Google Access
        syncer.sync_single_user_visas(
            gen3_user, ga4gh_visas, db_session, expiration=expiration
        )


def put_gen3_usernames_for_passport_into_cache(passport, usernames_from_passports):
    pass
