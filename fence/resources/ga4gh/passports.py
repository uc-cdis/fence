import base64
import flask
import httpx

from authutils.errors import JWTError
from authutils.token.core import get_iss, get_keys_url, get_kid, validate_jwt
from authutils.token.keys import get_public_key_for_token
from cdislogging import get_logger
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from fence.config import config

logger = get_logger(__name__)


def get_gen3_user_ids_from_ga4gh_passports(passports):

    user_ids_from_passports = []

    was_cached = False
    raw_visas = []
    for passport in passports:
        try:
            # TODO check cache
            cached_user_ids = get_gen3_user_ids_for_passport_from_cache(passport)

            if cached_user_ids:
                # existence in the cache means that this passport was validated
                # previously
                user_ids_from_passports.extend(cached_user_ids)
                was_cached = True
                continue

            # below function also validates passport (or raises exception)
            raw_visas.extend(get_unvalidated_visas_from_valid_passport(passport))
        except Exception as exc:
            logger.warning(f"invalid passport provided, ignoring. Error: {exc}")
            continue

    for raw_visa in raw_visas:
        try:
            # below function also validates visa (or raises exception) and
            # extracts the subject id
            subject_id, issuer = get_sub_iss_from_visa(raw_visa)

            # query idp user table
            gen3_user = get_or_create_gen3_user_from_sub_iss(subject_id, issuer)
            user_ids_from_passports.append(gen3_user.id)

        except Exception as exc:
            logger.warning(f"invalid visa provided, ignoring. Error: {exc}")
            continue

        # NOTE: does not validate, assumes validation occurs above.
        sync_visa_authorization(raw_visa)

        if not was_cached:
            put_gen3_user_ids_for_passport_into_cache(passport, user_ids_from_passports)

    return users_from_passports


def get_gen3_user_ids_for_passport_from_cache(passport):
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
        if flask.has_app_context() and flask.current_app.pkey_cache:
            pkey_cache = flask.current_app.pkey_cache
        else:
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
    if not public_key:
        try:
            logger.info("Fetching public key from flask app...")
            public_key = get_public_key_for_token(passport, attempt_refresh=True)
        except Exception as e:
            logger.info(
                "Could not fetch public key from flask app to validate passport: {}. Trying to fetch from source.".format(
                    e
                )
            )
            try:
                logger.info("Trying to Fetch public keys from JWKs url...")
                public_key = refresh_pkey_cache(
                    passport_issuer, passport_kid, pkey_cache
                )
            except Exception as e:
                logger.info(
                    "Could not fetch public key from JWKs key url: {}".format(e)
                )
    if not public_key:
        logger.error(
            "Could not fetch public key to validate visa: Successfully fetched "
            "issuer's keys but did not find the visa's key id among them. Discarding visa."
        )
    try:
        decoded_passport = validate_jwt(
            passport,
            public_key,
            aud=None,
            scope={"openid"},
            issuers=config.get("GA4GH_VISA_ISSUER_ALLOWLIST", []),
            options={
                "require_iat": True,
                "require_exp": True,
            },
        )
    except Exception as e:
        logger.error("Passport failed validation: {}. Discarding passport.".format(e))
        # ignore malformed/invalid passports
        return []

    return decoded_passport.get("ga4gh_passport_v1", [])


def is_raw_visa_valid(raw_visa):
    # check signature
    # is a type we recognize?
    return False


def get_sub_iss_from_visa(raw_visa):
    if not is_valid_visa(raw_visa):
        raise Exception()

    subject_id = None
    issuer = None

    # TODO

    return subject_id, issuer


def sync_valid_visa_authorization(visa):
    # DOES NOT VALIDATE VISA

    # syncs authz to backend

    pass


def get_or_create_gen3_user_from_sub_iss(subject_id, issuer):
    # TODO query idp user table, not there, create user and add row
    return None


def sync_visa_authorization(raw_visa):
    pass


def put_gen3_user_ids_for_passport_into_cache(passport, user_ids_from_passports):
    pass


def refresh_pkey_cache(issuer, kid, pkey_cache):
    """
    Update app public key cache for a specific Passport Visa issuer

    Args:
        issuer(str): Passport Visa issuer. Can be found under `issuer` in a Passport or a Visa
        kid(str): Passsport Visa kid. Can be found in the header of an encoded Passport or encoded Visa
        pkey_cache (dict): app cache of public keys_dir

    Return:
        dict: public key for given issuer
    """
    jwks_url = get_keys_url(issuer)
    try:
        jwt_public_keys = httpx.get(jwks_url).json()["keys"]
    except Exception as e:
        raise JWTError(
            "Could not get public key to validate Passport/Visa: Could not fetch keys from JWKs url: {}".format(
                e
            )
        )

    issuer_public_keys = {}
    try:
        for key in jwt_public_keys:
            if "kty" in key and key["kty"] == "RSA":
                logger.debug(
                    "Serializing RSA public key (kid: {}) to PEM format.".format(
                        key["kid"]
                    )
                )
                # Decode public numbers https://tools.ietf.org/html/rfc7518#section-6.3.1
                n_padded_bytes = base64.urlsafe_b64decode(
                    key["n"] + "=" * (4 - len(key["n"]) % 4)
                )
                e_padded_bytes = base64.urlsafe_b64decode(
                    key["e"] + "=" * (4 - len(key["e"]) % 4)
                )
                n = int.from_bytes(n_padded_bytes, "big", signed=False)
                e = int.from_bytes(e_padded_bytes, "big", signed=False)
                # Serialize and encode public key--PyJWT decode/validation requires PEM
                rsa_public_key = rsa.RSAPublicNumbers(e, n).public_key(
                    default_backend()
                )
                public_bytes = rsa_public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                # Cache the encoded key by issuer
                issuer_public_keys[key["kid"]] = public_bytes
            else:
                logger.debug(
                    "Key type (kty) is not 'RSA'; assuming PEM format. "
                    "Skipping key serialization. (kid: {})".format(key[0])
                )
                issuer_public_keys[key[0]] = key[1]

        pkey_cache.update({issuer: issuer_public_keys})
        logger.info(
            "Refreshed cronjob pkey cache for Passport/Visa issuer {}".format(issuer)
        )
    except Exception as e:
        logger.error(
            "Could not refresh cronjob pkey cache for issuer {}: "
            "Something went wrong during serialization: {}. Discarding Passport/Visa.".format(
                issuer, e
            )
        )

    if flask.has_app_context():
        flask.current_app.pkey_cache = pkey_cache

    return pkey_cache.get(issuer, {}).get(kid)
