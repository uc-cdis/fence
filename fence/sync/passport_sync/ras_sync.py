import jwt
import time

from fence.sync.passport_sync.base_sync import DefaultVisa


class RASVisa(DefaultVisa):
    """
    Class representing RAS visas
    """

    def __init__(self, logger):
        super(RASVisa, self).__init__(
            logger=logger,
        )

    def _parse_single_visa(
        self, user, encoded_visa, expires, parse_consent_code, db_session
    ):
        """
        Return user information from the visa.

        IMPORTANT NOTE: THIS DOES NOT VALIDATE THE ENCODED VISA. ENSURE THIS IS DONE
                        BEFORE THIS.
        """
        decoded_visa = {}

        # do not verify again, assume this happens upstream
        # note that this can fail, upstream should handle the case that parsing fails
        decoded_visa = jwt.decode(encoded_visa, verify=False)

        ras_dbgap_permissions = decoded_visa.get("ras_dbgap_permissions", [])
        project = {}
        info = {}
        info["tags"] = {}

        if time.time() >= expires:
            raise Exception("visa is expired")

        for permission in ras_dbgap_permissions:
            phsid = permission.get("phs_id", "")
            consent_group = permission.get("consent_group", "")
            full_phsid = phsid
            if parse_consent_code and consent_group:
                full_phsid += "." + consent_group
            privileges = {"read-storage", "read"}
            permission_expiration = permission.get("expiration")
            if permission_expiration and expires <= permission_expiration:
                project[full_phsid] = privileges
                info["tags"] = {"dbgap_role": permission.get("role", "")}

        info["email"] = user.email or ""
        info["display_name"] = user.display_name or ""
        info["phone_number"] = user.phone_number or ""
        return project, info
