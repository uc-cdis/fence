class DefaultVisa(object):
    """
    Base class for representation of information in a GA4GH passport describing user, project, and ABAC
    information for access control
    """

    def __init__(
        self,
        logger=None,
    ):
        self.logger = logger
        # add option for DB and dbsession

    def _parse_single_visa(self, user, visa):
        pass
