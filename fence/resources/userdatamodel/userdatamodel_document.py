from fence.errors import NotFound, UserError
from fence.models import (
    User,
    Document,
    UserDocument
)

__all__ = [
    "add_document",
]


def add_document(current_session, document_json):
    """
    Creates a project with an associated auth_id and storage access
    """
    new_document = Document(document_json)
    current_session.add(new_document)
    current_session.flush()
    return new_document