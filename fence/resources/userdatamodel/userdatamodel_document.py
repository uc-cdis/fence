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
    new_document = Document(type=document_json["type"],
                        version=document_json["version"], 
                        name=document_json["name"],
                        required=document_json["required"],
                        raw=document_json["raw"],
                        formatted=document_json["formatted"])
    current_session.add(new_document)
    current_session.commit()
    return new_document