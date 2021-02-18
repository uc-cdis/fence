import jwt
import time

from fence.sync.passport_sync.base_sync import DefaultVisa


class RASVisa(DefaultVisa):
    """
    Class representing RAS visas
    """

    def _init__(self, logger):
        super(RASVisa, self).__init__(
            logger=logger,
        )

    def _parse_single_visa(
        self, user, encoded_visa, expires, parse_consent_code, db_session
    ):
        decoded_visa = {}
        try:
            decoded_visa = jwt.decode(encoded_visa, verify=False)
        except Exception as e:
            self.logger.warning("Couldn't decode visa {}".format(e))
            # Remove visas if its invalid or expired
            user.ga4gh_visas_v1 = []
            db_session.commit()
        finally:
            ras_dbgap_permissions = decoded_visa.get("ras_dbgap_permissions", [])
        project = {}
        info = {}
        info["tags"] = {}

        if time.time() < expires:
            for permission in ras_dbgap_permissions:
                phsid = permission.get("phs_id", "")
                version = permission.get("version", "")
                participant_set = permission.get("participant_set", "")
                consent_group = permission.get("consent_group", "")
                full_phsid = phsid
                if parse_consent_code and consent_group:
                    full_phsid += "." + consent_group
                privileges = {"read-storage", "read"}
                project[full_phsid] = privileges
                info["tags"] = {"dbgap_role": permission.get("role", "")}
        else:
            # Remove visas if its invalid or expired
            user.ga4gh_visas_v1 = []
            db_session.commit()

        info["email"] = user.email or ""
        info["display_name"] = user.display_name or ""
        info["phone_number"] = user.phone_number or ""
        return project, info
