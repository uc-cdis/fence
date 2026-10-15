#!/bin/bash

#
# Kubernetes may mount jwt-keys as a tar ball
#
if [ -f /fence/jwt-keys.tar ]; then
  (
    cd /fence
    tar xvf jwt-keys.tar
    if [ -d jwt-keys ]; then
      # Replace keys/ rather than merging into it. Anything already there came
      # from the image build rather than from the mounted secret, and must not
      # survive alongside - fence loads every keypair it finds and publishes
      # each one in the JWKS.
      rm -rf keys
      mkdir -p keys
      mv jwt-keys/* keys/
    fi
  )
fi

nginx
poetry run gunicorn -c "/fence/deployment/wsgi/gunicorn.conf.py"
