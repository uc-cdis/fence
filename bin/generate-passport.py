import argparse
import os
import time
import jwt

"""
Generates a passport for testing.
"""

DEFAULT_EXPIRATION = 3600
DEFAULT_ISSUER = "https://gen3.datacommons.io"

BASE_LINKED_IDENTITY_VISA = {
    "iss": DEFAULT_ISSUER,
    "sub": "9440e1",
    "iat": int(time.time()),
    "exp": int(time.time()) + DEFAULT_EXPIRATION,
    "jti": "f7c04de3-5384-4abd-9977-d25da896dd66",
    "scope": "openid ga4gh_passport_v1",
    "txn": "ad6479eb.83635ace",
    "ga4gh_visa_v1": {
        "type": "LinkedIdentities",
        "asserted": 1787788838,
        "value": "9440e1,https://gen3.datacommons.io/;fae584,https://caninedc.org/",
        "source": "https://gen3.datacommons.io/",
        "by": "gen3.org",
    },
}

BASE_MOCK_RAS_VISA = {
    "iss": DEFAULT_ISSUER,
    "sub": "9440e1",
    "iat": int(time.time()),
    "exp": int(time.time()) + DEFAULT_EXPIRATION,
    "scope": "openid ga4gh_passport_v1",
    "jti": "69105145-8167-4d8b-a114-73e9f94fb63d",
    "txn": "ad6479eb.83635ace",
    "ga4gh_visa_v1": {
        "type": "https://ras.nih.gov/visas/v1.1",
        "asserted": 1787788838,
        "value": "https://stsstg.nih.gov/passport/dbgap/v1.1",
        "source": "https://ncbi.nlm.nih.gov/gap",
        "by": "dac",
    },
    "ras_dbgap_permissions": [
        {
            "consent_name": "Unrestricted",
            "phs_id": "phs000710",
            "version": "v1",
            "participant_set": "p1",
            "consent_group": "c99",
            "role": "pi",
            "expiration": int(time.time()) + DEFAULT_EXPIRATION,
        },
        {
            "consent_name": "General Research Use (NPU)",
            "phs_id": "phs002410",
            "version": "v1",
            "participant_set": "p1",
            "consent_group": "c2",
            "role": "designated user",
            "expiration": int(time.time()) + DEFAULT_EXPIRATION,
        },
        {
            "consent_name": "Health/Medical/Biomedical",
            "phs_id": "phs002410",
            "version": "v1",
            "participant_set": "p1",
            "consent_group": "c3",
            "role": "designated user",
            "expiration": int(time.time()) + DEFAULT_EXPIRATION,
        },
    ],
}

BASE_PASSPORT = {
    "sub": "9440e1",
    "jti": "90e76d20-9e8e-4fe3-a92d-25b7b5136178",
    "scope": "openid ga4gh_passport_v1",
    "txn": "ad6479eb.83635ace",
    "iss": DEFAULT_ISSUER,
    "iat": int(time.time()),
    "exp": int(time.time()) + DEFAULT_EXPIRATION,
    "ga4gh_passport_v1": [],
}
# Don't panic -- this private key is from https://pyjwt.readthedocs.io/en/stable/usage.html
PRIVATE_KEY = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAwhvqCC+37A+UXgcvDl+7nbVjDI3QErdZBkI1VypVBMkKKWHM\nNLMdHk0bIKL+1aDYTRRsCKBy9ZmSSX1pwQlO/3+gRs/MWG27gdRNtf57uLk1+lQI\n6hBDozuyBR0YayQDIx6VsmpBn3Y8LS13p4pTBvirlsdX+jXrbOEaQphn0OdQo0WD\noOwwsPCNCKoIMbUOtUCowvjesFXlWkwG1zeMzlD1aDDS478PDZdckPjT96ICzqe4\nO1Ok6fRGnor2UTmuPy0f1tI0F7Ol5DHAD6pZbkhB70aTBuWDGLDR0iLenzyQecmD\n4aU19r1XC9AHsVbQzxHrP8FveZGlV/nJOBJwFwIDAQABAoIBAFCVFBA39yvJv/dV\nFiTqe1HahnckvFe4w/2EKO65xTfKWiyZzBOotBLrQbLH1/FJ5+H/82WVboQlMATQ\nSsH3olMRYbFj/NpNG8WnJGfEcQpb4Vu93UGGZP3z/1B+Jq/78E15Gf5KfFm91PeQ\nY5crJpLDU0CyGwTls4ms3aD98kNXuxhCGVbje5lCARizNKfm/+2qsnTYfKnAzN+n\nnm0WCjcHmvGYO8kGHWbFWMWvIlkoZ5YubSX2raNeg+YdMJUHz2ej1ocfW0A8/tmL\nwtFoBSuBe1Z2ykhX4t6mRHp0airhyc+MO0bIlW61vU/cPGPos16PoS7/V08S7ZED\nX64rkyECgYEA4iqeJZqny/PjOcYRuVOHBU9nEbsr2VJIf34/I9hta/mRq8hPxOdD\n/7ES/ZTZynTMnOdKht19Fi73Sf28NYE83y5WjGJV/JNj5uq2mLR7t2R0ZV8uK8tU\n4RR6b2bHBbhVLXZ9gqWtu9bWtsxWOkG1bs0iONgD3k5oZCXp+IWuklECgYEA27bA\n7UW+iBeB/2z4x1p/0wY+whBOtIUiZy6YCAOv/HtqppsUJM+W9GeaiMpPHlwDUWxr\n4xr6GbJSHrspkMtkX5bL9e7+9zBguqG5SiQVIzuues9Jio3ZHG1N2aNrr87+wMiB\nxX6Cyi0x1asmsmIBO7MdP/tSNB2ebr8qM6/6mecCgYBA82ZJfFm1+8uEuvo6E9/R\nyZTbBbq5BaVmX9Y4MB50hM6t26/050mi87J1err1Jofgg5fmlVMn/MLtz92uK/hU\nS9V1KYRyLc3h8gQQZLym1UWMG0KCNzmgDiZ/Oa/sV5y2mrG+xF/ZcwBkrNgSkO5O\n7MBoPLkXrcLTCARiZ9nTkQKBgQCsaBGnnkzOObQWnIny1L7s9j+UxHseCEJguR0v\nXMVh1+5uYc5CvGp1yj5nDGldJ1KrN+rIwMh0FYt+9dq99fwDTi8qAqoridi9Wl4t\nIXc8uH5HfBT3FivBtLucBjJgOIuK90ttj8JNp30tbynkXCcfk4NmS23L21oRCQyy\nlmqNDQKBgQDRvzEB26isJBr7/fwS0QbuIlgzEZ9T3ZkrGTFQNfUJZWcUllYI0ptv\ny7ShHOqyvjsC3LPrKGyEjeufaM5J8EFrqwtx6UB/tkGJ2bmd1YwOWFHvfHgHCZLP\n34ZNURCvxRV9ZojS1zmDRBJrSo7+/K0t28hXbiaTOjJA18XAyyWmGg==\n-----END RSA PRIVATE KEY-----\n"  # pragma: allowlist secret


def read_private_key(path):
    """
    Read a PEM-encoded private key from an absolute path on disk.
    """
    if not os.path.isabs(path):
        raise argparse.ArgumentTypeError(
            "must be an absolute path, got: {}".format(path)
        )
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError("no such file: {}".format(path))
    with open(path, "rb") as private_key_file:
        return private_key_file.read()


def encode(payload, private_key, kid):
    """
    Sign a payload, including "kid" in the header when one was provided.
    Fence only refreshes an issuer's public keys when the token carries a
    "kid", so without one validation fails with "Public key for issuer
    <iss> not found."
    """
    headers = {"kid": kid} if kid else None
    return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--issuer",
        default=DEFAULT_ISSUER,
        help="Issuer to use for the passport and all visas (default: %(default)s)",
    )
    parser.add_argument(
        "--linked-identity-issuer",
        help="Override the issuer of the LinkedIdentities visa only",
    )
    parser.add_argument(
        "--ras-visa-issuer",
        help="Override the issuer of the mock RAS visa only",
    )
    parser.add_argument(
        "--passport-issuer",
        help="Override the issuer of the passport only",
    )
    parser.add_argument(
        "--kid",
        help="Key id to put in the header of the passport and all visas. "
        "Must match a kid published in the issuer's JWKS.",
    )
    parser.add_argument(
        "--linked-identity-kid",
        help="Override the key id of the LinkedIdentities visa only",
    )
    parser.add_argument(
        "--ras-visa-kid",
        help="Override the key id of the mock RAS visa only",
    )
    parser.add_argument(
        "--passport-kid",
        help="Override the key id of the passport only",
    )
    parser.add_argument(
        "--private-key",
        type=read_private_key,
        default=PRIVATE_KEY,
        metavar="PATH",
        help="Absolute path to a file containing the PEM-encoded RSA private "
        "key to sign with (default: the hardcoded pyjwt example key)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    BASE_LINKED_IDENTITY_VISA["iss"] = args.linked_identity_issuer or args.issuer
    BASE_MOCK_RAS_VISA["iss"] = args.ras_visa_issuer or args.issuer
    BASE_PASSPORT["iss"] = args.passport_issuer or args.issuer

    linked_identity_visa = encode(
        BASE_LINKED_IDENTITY_VISA,
        args.private_key,
        args.linked_identity_kid or args.kid,
    )
    ras_visa = encode(
        BASE_MOCK_RAS_VISA, args.private_key, args.ras_visa_kid or args.kid
    )

    BASE_PASSPORT["ga4gh_passport_v1"] = [linked_identity_visa, ras_visa]
    passport = encode(BASE_PASSPORT, args.private_key, args.passport_kid or args.kid)
    print(passport)
