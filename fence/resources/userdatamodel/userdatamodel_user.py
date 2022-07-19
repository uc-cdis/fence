from sqlalchemy import func, and_
from cdislogging import get_logger
from fence.errors import NotFound, UserError
from fence.models import (
    Project,
    StorageAccess,
    CloudProvider,
    ProjectToBucket,
    Bucket,
    User,
    AccessPrivilege,
    Group,
    UserToGroup,
    query_for_user,
    Document,
    UserDocument
)

__all__ = [
    "get_user",
    "get_user_accesses",
    "create_user_by_username_project",
    "get_all_users",
    "get_users",
    "get_users_by_id",
    "get_user_groups",
    "update_user",
    "review_document",
    "get_doc_to_review",
    "get_docs",
    "get_latest_doc_by_type",
]

logger = get_logger(__name__)

def get_user(current_session, username):
    return query_for_user(session=current_session, username=username)

def update_user(current_session, username, additional_info):
    updated_user = current_session.query(User).filter(User.username == username).update({User.additional_info: additional_info})
    current_session.commit()
    return updated_user

def get_user_accesses(current_session):
    return (
        current_session.query(User).join(User.groups).filter(User.id == flask.g.user.id)
    )


def create_user_by_username_project(current_session, new_user, proj):
    """
    Create a user for a specific project
    """
    project = (
        current_session.query(Project)
        .filter(Project.auth_id == proj["auth_id"])
        .first()
    )
    if not project:
        msg = "".join(["error: auth_id name ", proj["auth_id"], " not found"])
        raise NotFound(msg)

    # If am enforcing a full match.
    # The table has keys that only comprehend two of the arguments
    # I will address that option later.
    # For now, we need a full match to replace or update
    priv = (
        current_session.query(AccessPrivilege)
        .filter(
            AccessPrivilege.user_id == new_user.id,
            AccessPrivilege.project_id == project.id,
        )
        .first()
    )
    if priv:
        # I update the only updatable field
        priv.privilege = proj["privilege"]
    else:
        priv = AccessPrivilege(
            user_id=new_user.id, project_id=project.id, privilege=proj["privilege"]
        )
        current_session.add(priv)
        current_session.flush()

    return {"user": new_user, "project": project, "privileges": priv}


def get_all_users(current_session):
    return current_session.query(User).all()


def get_users(current_session, usernames:list):
    # logger.debug(f"get_users usernames: {usernames}")
    if not usernames:
        return []
    users = current_session.query(User).filter(
        User.username.in_(usernames)
    ).all()
    # logger.debug(f"get_users users found: {users}")
    return users

def get_users_by_id(current_session, ids:list):
    if not ids:
        return []
    users = current_session.query(User).filter(
        User.id.in_(ids)
    ).all()
    return users


def get_user_groups(current_session, username):
    user = get_user(current_session, username)
    groups_to_list = current_session.query(UserToGroup).filter(
        UserToGroup.user_id == user.id
    )
    groups = []
    for group in groups_to_list:
        group_to_retrieve = (
            current_session.query(Group).filter(Group.id == group.group_id).first()
        )
        groups.append(group_to_retrieve.name)
    return {"groups": groups}


def review_document(session, username, documents):
    user = get_user(session, username)
    if not user:
        msg = "".join(["error: user with username ", user["username"], " not found"])
        raise NotFound(msg)

    user_docs = []
    added_docs = []
    for key, value in documents.items():
        doc = session.query(Document).filter(Document.id == key).first()

        if doc and not (doc.required == True and value == False):
            added_docs.append(doc)
            new_user_doc = UserDocument(user_id=user.id, document_id=doc.id, accepted=value)
            user_docs.append(new_user_doc)

    if len(user_docs) > 0:
        # user.documents.extend(docs)
        session.add_all(user_docs)
        session.commit()
        
    return added_docs


def get_doc_to_review(session, username):
    # get latest docs
    latest_docs_subq = (
        session.query(Document.type, func.max(Document.version).label("version"))
        .group_by(Document.type)
        .subquery("latest_doc")
    )
    latest_docs = (
        session.query(Document)
        .join(
            latest_docs_subq,
            and_(
                Document.type == latest_docs_subq.c.type,
                Document.version == latest_docs_subq.c.version,
                Document.required == True,
            ),
        )
        .all()
    )

    # get user documents
    user_docs = (
        session.query(UserDocument)
        .join(User)
        .filter(func.lower(User.username) == username.lower())
        .join(Document)
        .join(
            latest_docs_subq,
            and_(
                Document.type == latest_docs_subq.c.type,
                Document.version == latest_docs_subq.c.version,
            ),
        )
        .all()
    )

    user_docs_id = [user_doc.document.id for user_doc in user_docs]
    docs = [latest_doc for latest_doc in latest_docs if latest_doc.id not in user_docs_id]

    # docs = []
    # for doc in latest_docs:
    #     present = False
    #     for user_doc in user_docs:
    #         if doc.id == user_doc.document.id:
    #             present = True 

    #     if not present:
    #         docs.append(doc)

    return docs

def get_docs(session):
    latest_docs_subq = (
        session.query(Document.type, func.max(Document.version).label("version"))
        .group_by(Document.type)
        .subquery("latest_doc")
    )
    latest_docs = (
        session.query(Document)
        .join(
            latest_docs_subq,
            and_(
                Document.type == latest_docs_subq.c.type,
                Document.version == latest_docs_subq.c.version,
            ),
        )
        .all()
    )

    return latest_docs

def get_latest_doc_by_type(session, type):
    latest_doc = (
        session.query(Document)
        .filter(Document.type == type)
        .order_by(Document.version.desc())
        .first()
    )
    return latest_doc


