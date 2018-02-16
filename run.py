from mock import patch

from cdisutilstest.code.storage_client_mock import get_client

from fence import app, app_config, app_sessions
from fence.oidc.server import server

app_config(app)

if app.config.get('MOCK_STORAGE', False):
    patcher = patch(
        'fence.resources.storage.get_client',
        get_client)
    patcher.start()

server.init_app(app)
app_sessions(app)
app.run(debug=True, port=8000)
