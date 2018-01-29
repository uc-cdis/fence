"""
OIDC specification of authentication request parameter ``acr_values``:

    OPTIONAL. Requested Authentication Context Class Reference values.
    Space-separated string that specifies the ``acr`` values that the
    Authorization Server is being requested to use for processing this
    Authentication Request, with the values appearing in order of preference.
    The Authentication Context Class satisfied by the authentication performed
    is returned as the ``acr`` Claim Value, as specified in Section 2. The
    ``acr`` Claim is requested as a Voluntary Claim by this parameter.
"""
