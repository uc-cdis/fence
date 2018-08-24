#!/bin/bash

#
# Update certificate authority index -
# environment may have mounted more authorities
#
update-ca-certificates
#
# Enable debug flag based on GEN3_DEBUG environment
#
if [[ -f ./wsgi.py && "$GEN3_DEBUG" == "True" ]]; then
  echo -e "\napplication.debug=True\n" >> ./wsgi.py
fi  
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
    fi
  )
fi
rm -rf /var/run/apache2/apache2.pid
/usr/sbin/apache2ctl -D FOREGROUND
