from fence import (
    app,
    app_config,
    app_config_oauth,
    app_register_blueprints,
    app_sessions,
)
from fence.oidc.server import server

app_config(app)
app_config_oauth(app)

if app.config.get("MOCK_STORAGE"):
    from mock import patch
    from cdisutilstest.code.storage_client_mock import get_client

    patcher = patch("fence.resources.storage.get_client", get_client)
    patcher.start()

app_sessions(app)
app_register_blueprints(app)
server.init_app(app)
app.run(debug=True, port=8000)
