from fence import app, app_config, app_sessions
from mock import patch
from cdisutilstest.code.storage_client_mock import get_client
from fence.blueprints.oauth2 import init_oauth

app_config(app)

if app.config.get('MOCK_STORAGE', False):
    patcher = patch(
        'fence.resources.storage.get_client',
        get_client)
    patcher.start()

init_oauth(app)
app_sessions(app)
app.run(debug=True, port=8000)
