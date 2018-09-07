import datetime
from cryptography.fernet import Fernet

from fence.errors import UserError, NotFound
from fence.models import HMACKeyPair
from fence.utils import random_str


def create_keypair(user, current_session, encryption_key, expire=86400):
    existing_keypairs = 0
    for keypair in user.hmac_keypairs:
        if not keypair.check_and_archive(current_session):
            existing_keypairs += 1
    if existing_keypairs >= 2:
        raise UserError("You can only have at most 2 keypairs")

    key = Fernet(encryption_key)
    # default to 1 day, max to 30 days
    try:
        expire = int(expire)
    except ValueError:
        raise UserError(
            "Expiration has to be an integer representing" " expiration time in seconds"
        )
    if expire > 2592000:
        raise UserError("Max expiration time is 30 days(2592000 seconds)")
    expire = min(expire, 2592000)

    result = dict(access_key=random_str(20), secret_key=random_str(40))
    keypair = HMACKeyPair(
        access_key=result["access_key"],
        secret_key=key.encrypt(result["secret_key"]),
        expire=expire,
        user_id=user.id,
    )
    current_session.add(keypair)
    current_session.commit()
    return result


def delete_keypair(user, current_session, access_key):
    result = (
        current_session.query(HMACKeyPair)
        .filter(HMACKeyPair.access_key == access_key)
        .filter(HMACKeyPair.user_id == user.id)
        .first()
    )
    if not result:
        raise NotFound("Access key doesn't exist")
    result.archive_keypair(current_session)


def list_keypairs(user, current_session):
    result = []
    for keypair in user.hmac_keypairs:
        if not keypair.check_and_archive(current_session):
            result.append(
                dict(
                    access_key=keypair.access_key,
                    expire=str(
                        keypair.timestamp + datetime.timedelta(seconds=keypair.expire)
                    ),
                )
            )
    return result
