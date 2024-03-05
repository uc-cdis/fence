from fence.resources.storage.storageclient.cleversafe import CleversafeClient
from fence.resources.storage.storageclient.google import GoogleCloudStorageClient


def get_client(config=None, backend=None):
    try:
        clients = {"cleversafe": CleversafeClient, "google": GoogleCloudStorageClient}
        return clients[backend](config)
    except KeyError as ex:
        raise NotImplementedError(
            "The input storage is currently not supported!: {0}".format(ex)
        )
