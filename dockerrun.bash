#!/bin/bash

#
# Update certificate authority index -
# environment may have mounted more authorities
#
update-ca-certificates
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

if [ ! -z $NGINX_RATE_LIMIT ]; then
  echo "Found NGINX_RATE_LIMIT environment variable..."
  contains_rate_limit_override=$(cat /var/www/fence/fence-config.yaml | grep OVERRIDE_NGINX_RATE_LIMIT)
  RC=$?
  if [[ $RC -eq 0 ]]; then
    rate_limit=$(echo $contains_rate_limit_override | cut -d"=" -f 2 | xargs)
    echo "Applying new Nginx rate limit ${rate_limit}..."

    # Add rate_limit config
    rate_limit_conf="\ \ \ \ limit_req_zone \$binary_remote_addr zone=one:10m rate=${rate_limit}r/s;"
    sed -i "/http\ {/a ${rate_limit_conf}" /etc/nginx/nginx.conf
    if [ -f /etc/nginx/sites-available/uwsgi.conf ]; then
      limit_req_config="\ \ \ \ \ \ \ \ limit_req zone=one;"
      sed -i "/location\ \/\ {/a ${limit_req_config}" /etc/nginx/sites-available/uwsgi.conf
    fi
  fi
fi
