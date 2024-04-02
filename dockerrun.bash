#!/bin/bash

#
# Update certificate authority index -
# environment may have mounted more authorities
#
# update-ca-certificates
#
# Kubernetes may mount jwt-keys as a tar ball
#
if [ -f /fence/jwt-keys.tar ]; then
  (
    cd /fence
    tar xvf jwt-keys.tar
    if [ -d jwt-keys ]; then
      mkdir -p keys
      mv jwt-keys/* keys/
      rm -rf /fence/keys/key/
    fi
  )
fi

gunicorn -c /fence/deployment/wsgi/gunicorn.conf.py
