from cdislogging import get_logger

from fence.resources import userdatamodel as udm


__all__ = [
    "add_document",
]

logger = get_logger(__name__)

def add_document(current_session, document_json):
    """
    Return the information associated with a project
    Returns a dictionary.
    """
    doc = udm.get_latest_doc_by_type(current_session, document_json["type"])

    if doc and doc.version and int(document_json["version"]) <= doc.version:
        logger.info("Version provided {} will be changed to {}.".format(document_json["version"], doc.version))
        document_json['version'] = doc.version + 1

    return udm.add_document(current_session, document_json)


