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

    def _parse_single_visa(self, user, encoded_visa, expires, parse_consent_code):
        """
        Return user information from the visa.

        IMPORTANT NOTE: THIS DOES NOT VALIDATE THE ENCODED VISA. ENSURE THIS IS DONE
                        BEFORE THIS.
        """
        decoded_visa = {}

        # do not verify again, assume this happens upstream
        # note that this can fail, upstream should handle the case that parsing fails
        decoded_visa = jwt.decode(
            encoded_visa, algorithms=["RS256"], options={"verify_signature": False}
        )

        ras_dbgap_permissions = decoded_visa.get("ras_dbgap_permissions", [])
        project = {}
        info = {}
        info["tags"] = {}

        if time.time() < expires:
            for permission in ras_dbgap_permissions:
                phsid = permission.get("phs_id", "")
                consent_group = permission.get("consent_group", "")

                if not phsid or not consent_group:
                    self.logger.error(
                        f"cannot determine visa permission for phsid {phsid} "
                        f"and consent_group {consent_group}. Ignoring this permission."
                    )
                else:
                    full_phsid = str(phsid)
                    if parse_consent_code and consent_group:
                        full_phsid += "." + str(consent_group)
                    privileges = {"read-storage", "read"}

                    permission_expiration = None
                    try:
                        permission_expiration = int(permission.get("expiration", 0))
                    except Exception as exc:
                        self.logger.error(
                            f"cannot determine visa expiration for {full_phsid} "
                            f"from: {permission.get('expiration')}. Ignoring this permission."
                        )

                    if permission_expiration and expires <= permission_expiration:
                        project[full_phsid] = privileges
                        info["tags"] = {"dbgap_role": permission.get("role", "")}
                    else:
                        self.logger.info(
                            f"dbGaP permission for {full_phsid} expired at {permission_expiration}"
                        )
        else:
            # Remove visas if its invalid or expired
            user.ga4gh_visas_v1 = []
            db_session.commit()

        info["email"] = user.email or ""
        info["display_name"] = user.display_name or ""
        info["phone_number"] = user.phone_number or ""
        return project, info
