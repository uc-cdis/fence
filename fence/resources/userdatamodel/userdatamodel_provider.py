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
)


__all__ = ["create_provider", "get_provider", "delete_provider"]


def create_provider(
    current_session,
    provider_name,
    backend=None,
    service=None,
    endpoint=None,
    description=None,
):
    """
    Create a new provider on the table
    """
    check = (
        current_session.query(CloudProvider)
        .filter(CloudProvider.name == provider_name)
        .first()
    )
    if check:
        msg = (
            "provider name {} already in use; please choose a different name"
            " and try again"
        ).format(provider_name)
        raise UserError(msg)
    provider = CloudProvider(
        name=provider_name,
        backend=backend,
        service=service,
        endpoint=endpoint,
        description=description,
    )
    current_session.add(provider)
    msg = {"result": "success"}
    return msg


def get_provider(current_session, provider_name):
    """
    Get the provider info from the userdatamodel
    """
    provider = (
        current_session.query(CloudProvider)
        .filter(CloudProvider.name == provider_name)
        .first()
    )
    if not provider:
        msg = "".join(["error, cloud provider ", provider_name, " not found"])
        raise NotFound(msg)
    info = {
        "name": provider.name,
        "backend": provider.backend,
        "endpoint": provider.endpoint,
        "description": provider.description,
        "service": provider.service,
    }
    return info


def delete_provider(current_session, provider_name):
    """
    Delete a cloud provider if it has not
    ongoing relationships
    """
    provider = (
        current_session.query(CloudProvider)
        .filter(CloudProvider.name == provider_name)
        .first()
    )
    if not provider:
        msg = "provider name {}, not found"
        raise NotFound(msg.format(provider_name))

    projects = (
        current_session.query(StorageAccess)
        .filter(StorageAccess.provider_id == provider.id)
        .first()
    )
    if projects:
        msg = (
            "Provider name {} in use in projects."
            " Please remove these references and retry"
        )
        raise UserError(msg.format(provider_name))

    current_session.delete(provider)
    return {"response": "success"}
