from os import getuid, getgid
wsgi_app = "deployment.wsgi.wsgi:application"
bind = "0.0.0.0:8000"
workers = 1
preload_app = True
# Set user/group to the current user's UID and GID, unless UID is 0 (root), then set to 'gen3'
if getuid() == 0:
    user = "gen3"
    group = "gen3"
else:
    user = getuid()
    group = getgid()
timeout = 300
keepalive = 2
keepalive_timeout = 5
