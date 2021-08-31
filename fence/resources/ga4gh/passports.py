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


def get_unvalidated_visas_from_valid_passport(passport):
    # validate passport, return visas
    return []


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
