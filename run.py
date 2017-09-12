from fence import app, app_config, app_sessions, init_jwt
from mock import patch
from cdisutilstest.code.storage_client_mock import get_client

app_config(app)


app_sessions(app)
init_jwt(app)
app.run(debug=True, port=8181)
