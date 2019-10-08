#!/usr/bin/env python3
# pip install fastapi uvicorn
# cd tests
# LATENCY=1 uvicorn mock_synapse:app --port 8080

import asyncio
import os

import jwt
import time
from fastapi import FastAPI
from jwt.algorithms import RSAAlgorithm
from starlette.requests import Request

# generate new key pair
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.asymmetric import rsa
# private_key = rsa.generate_private_key(
#     public_exponent=65537, key_size=2048, backend=default_backend()
# )

private_key = RSAAlgorithm.from_jwk(
    '{"kty": "RSA", "key_ops": ["sign"], "n": "2cgA6eP6bBkrOg7MZCdvOPZ0TrC6tYrXEPxSlQLh'
    "SpQPs61B0y-N5SzqqCuQNSpjqUPTzmnlWlioa_tqSZ6IetprnAzzHwJ1oQoJDBQJGt30Xui5z_N126NkoN"
    "u4KlIvCzzYW-MWDSHhgyqUWaG6JrsbaEgFOjhrJux_5TesSVCT3s_3dxU1_w0xkr7UWIHF-Qr9M_ljDDLm"
    "CUnAOoVJYZfbZV3FjkOQXTQQTkMbYFQNhQ0Vxs9e1S0ZeePYlZSwgN8avGTRtXE7dQVQ9d0uKwsWLC44zF"
    'WqXbeROlNPoPU4TjZH5rzq3w3MxfOYvmzvnpCaR1RJtCj-KCTEzOb2UQ", "e": "AQAB", "d": "ve8t'
    "xM7cx8xHo_HmFm9CFFb1Zu_BVrWJDjpRt730SLvK2fSAFTRDN52t5g9gTM30b1pFbp9ytRHfiZWSxDQsaa"
    "D2-vlcTC4z8sgyzcLnkfQDvYaRD6kQoAbnq1cVTmuwtcdSFwl9YOSsrl3DVkyzcjX7GD6_uGAeK6tVe87L"
    "RoAQjdKxYXZUDIbpCVRlPenIbNM49qKuMuCYdsLjMpGTsnjT1QgEi3NtAAaHw-8oFoxJMgF6tvban53Urr"
    "tEMjNCkeLDMERelzhYaXG1fnMJ3oB5tefThqkNavvobjvdVETIPWKRJd9isUU-njWjR6uWFEnGwqyEF6VW"
    'LrFz1iLcQQ", "p": "-VrYc48XpRzaGreaedrtsIAV6PJvj7Ospwfr-NiCtCzIuiNWi7JS-gxiRxLSvlp'
    "cWq0aoZIMvXZ3wZ_iX8JOQ_acc8BvZzpWcPl4CBWyuuyMC-Q9eoHaibRjwbSDYS086IeyFsS_HlNsWBmEZ"
    'C7Bps8mduIRJQRGVjhpDQMOnLk", "q": "35XBgyl6SGpwTL2Q4iefujwYYx3SIQnjsTKTB1AAYMaym2J'
    "t4AmP2Z0Oiecur0-SbpjtElFkKvtWcEgLGzycsoo-1No3d3-VdeG8vSIuqvj5LbdfcRF1Jd2hYz2KHc-s8"
    '2yoQOoXqqMlKHaUPTQ_Hab1GaJQFFMvD-sTrS8tSlk", "dp": "KPVoKostmhyEIvFXuX5hnqVbc_kmpB'
    "ciXAlsFGMUDR5yFkkptSakhJg2KHCKF2RmWSqn_jQsTY7BGxf1Kj-TdYxzpHvOkMk_W61Orx1JT3T9iBKE"
    'mrPrvsTXwgCxt-ujXpqzgRPuRL_1Qv9mBMK9YnYSXmLB6C-skgsQDmgbJVk", "dq": "0IeYCIDy7_915'
    "d0X-BYEv2m1RRxXE0Fp_6avwq427AvmIU5YNBA2_juhh7T6sb-BT22KDv-icQQhxm8rDKgnbc3KdDNicC2"
    'qdFup8Kyk4gl8Pcs9VPN3U222TBzlaJB9OjwpYQH0OM4YpfiSodLM2xcQmmvsTEiZKDuUCn5pu2E", "qi'
    '": "fMlJAeKaKp31zBuXCzRYqOSjZAm6pm73B8HadjUi10nquuag-cIwuJlgs-IOl5A5S6irqGLQ8ycUU0'
    "Tk-AdyqGzRDM7vwuPkCMhXCi5BgJQyNEldlp0YlO-50cX0RtkHeH-JrgbNF9IV_v9VlVqYQjLhMc4Uuwhq"
    'zOyIQ9aS_7A"}'
)
public_key = private_key.public_key()

app = FastAPI()


@app.get("/")
def issuer():
    return {}


@app.get("/oauth2/authorize")
def auth():
    return {}


@app.post("/oauth2/token")
async def token():
    await asyncio.sleep(float(os.environ.get("LATENCY") or 0))
    email = os.environ.get("EMAIL") or "bob@example.com"
    given_name = os.environ.get("GIVEN_NAME") or "Bob"
    family_name = os.environ.get("FAMILY_NAME") or "Green"

    return dict(
        id_token=jwt.encode(
            dict(
                sub=email,
                email=email,
                email_verified=email,
                family_name=given_name,
                given_name=family_name,
                team=[os.environ.get("TEAM") or "0"],
                exp=str(int(time.time()) + int(os.environ.get("EXP") or 3600 * 24)),
            ),
            private_key,
            algorithm="RS256",
        )
    )


@app.get("/oauth2/userinfo")
def user_info():
    return {}


@app.get("/oauth2/jwks")
def jwks():
    return {
        "keys": [
            {
                "kid": "W7NN:WLJT:J5RK:L7TL:T7L7:3VX6:JEOU:644R:U3IX:5KZ2:7ZCK:FPTH",
                "kty": "RS256",
                "use": "SIGNATURE",
                "concreteType": "org.sagebionetworks.repo.model.oauth.JsonWebKeyRSA",
                "e": str(public_key.public_numbers().e),
                "n": str(public_key.public_numbers().n),
            }
        ]
    }


@app.get("/oauth2/client")
def reg():
    return {}


@app.get("/.well-known/openid-configuration")
def conf(req: Request):
    print()

    return dict(
        issuer=req.url_for("issuer"),
        authorization_endpoint=req.url_for("auth"),
        token_endpoint=req.url_for("token"),
        userinfo_endpoint=req.url_for("user_info"),
        jwks_uri=req.url_for("jwks"),
        registration_endpoint=req.url_for("reg"),
        scopes_supported=["openid"],
        response_types_supported=["code"],
        grant_types_supported=["authorization_code"],
        subject_types_supported=["pairwise"],
        id_token_signing_alg_values_supported=["RS256"],
        userinfo_signing_alg_values_supported=["RS256"],
        claims_supported=[
            "iss",
            "sub",
            "aud",
            "iat",
            "nbf",
            "exp",
            "auth_time",
            "email",
            "email_verified",
            "given_name",
            "family_name",
            "company",
            "team",
            "userid",
            "orcid",
            "is_certified",
            "is_validated",
            "validated_given_name",
            "validated_family_name",
            "validated_location",
            "validated_email",
            "validated_company",
            "validated_orcid",
            "validated_at",
        ],
        service_documentation="https://docs.synapse.org",
        claims_parameter_supported=True,
    )
