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

# add nginx status config
nginx_status_conf="\ \ \ \ location /nginx_status {\n\ \ \ \ \ \ stub_status;\n\ \ \ \ \ \ allow 127.0.0.1;\n\ \ \ \ \ \ deny all;\n\ \ \ \ \ \ access_log off;\n\ \ \ \ }"
sed -i "/\ \ \ \ error_page\ 502/i ${nginx_status_conf}" /etc/nginx/conf.d/uwsgi.conf

# add uwsgi status config
uwsgi_status_conf="\ \ \ \ location /uwsgi_status {\n\ \ \ \ \ \ proxy_pass \"http://127.0.0.1:9191\";\n\ \ \ \ \ \ allow 127.0.0.1;\n\ \ \ \ \ \ deny all;\n\ \ \ \ \ \ access_log off;\n\ \ \ \ }"
sed -i "/\ \ \ \ error_page\ 502/i ${uwsgi_status_conf}" /etc/nginx/conf.d/uwsgi.conf

# add another access log in a non-json format
additional_access_log_conf="\ \ \ \ access_log  /var/log/nginx/access_not_json.log main;"
sed -i "/\ \ \ \ access_log/a ${additional_access_log_conf}" /etc/nginx/nginx.conf
