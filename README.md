# Fence

## JWT

Example JWT issued by fence:
```
{
    "sub": "1234567",
    "iss": "dcfauth:56fc3842ccf2c1c7ec5c5d14",
    "iat": 1459458458,
    "exp": 1459487258,
    "jti": "56fd919accf2c1c7ec5c5d16",
    "aud": [
        "data",
        "iam",
    ],
    "context": {
        "user": {
            "name": "NIH_USERNAME",
            "projects": {
                "phs000178": ["member"],
                "phs000218": ["member", "submitter"],
            },
            "email": "user@university.edu",
        }
    }
}
```
