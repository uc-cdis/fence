import flask

HAS_KUBERNETES = True
try:
    # Import kubernetes, if it exists.
    import kubernetes
except ImportError:
    HAS_KUBERNETES = False

from fence.jwt import token
from fence.errors import Unauthorized
from fence.resources.user import find_user

blueprint = flask.Blueprint('internal', __name__)

POD_USERNAME_ANNOTATION = 'gen3username'
JUPYTER_POD_ANNOTATION = 'hub.jupyter.org/username'

@blueprint.route('/access_token', methods=['GET'])
def internal_access_token():
    '''
    Get an access token for the requesting k8s pod using
    the pod metadata label
    '''

    # If this request came in via proxy reject it
    # This isn't strictly necessary but short
    # circuits requests that come in publicly
    if 'X-Forwarded-For' in flask.request.headers:
        flask.abort(404)

    ip = flask.request.remote_addr
    username = get_username_from_ip(ip)
    if not username:
        raise Unauthorized('No matching pod found')

    expires_in = flask.current_app.config.get('MAX_ACCESS_TOKEN_TTL', 3600)
    keypair = flask.current_app.keypairs[0]
    scopes = ['fence', 'openid', 'user', 'data']

    with flask.current_app.db.session as session:
        user = find_user(username, session)
        access_token = token.generate_signed_access_token(
            keypair.kid, keypair.private_key, user, expires_in, scopes
        )

    return flask.jsonify(dict(access_token=access_token))


def get_username_from_ip(ip):
    # Fail if we can't load kubernetes config...
    try:
        kubernetes.config.load_incluster_config()
    except Exception:
        return None
    v1 = kubernetes.client.CoreV1Api()
    ret = v1.list_pod_for_all_namespaces(field_selector='status.podIP={}'.format(ip), watch=False)
    for pod in ret.items:
        if pod.metadata.annotations and POD_USERNAME_ANNOTATION in pod.metadata.annotations:
            return pod.metadata.annotations[POD_USERNAME_ANNOTATION]
        elif pod.metadata.annotations and JUPYTER_POD_ANNOTATION in pod.metadata.annotations:
            return pod.metadata.annotations[JUPYTER_POD_ANNOTATION]

    # No matching pod found
    return None
