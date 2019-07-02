#!/bin/bash
update-ca-certificates
mkdir /google_job
touch /google_job/status.json
echo '<virtualhost *:80>
    documentroot /google_job/

    aliasmatch ^/(.*)$ /google_job/status.json

    <directory "/google_job/status.json">
      require all granted
    </directory>
</virtualhost>' >/etc/nginx/sites-available/fence.conf

rm -rf /var/run/nginx.pid
/fence/dockerrun.bash

while [ $? -eq 0 ]; do
    echo start validation $(date)
    fence-create google-manage-user-registrations
    echo finish validation $(date)
    echo {\"last_run\": \"$(date)\"} >/google_job/status.json
done

