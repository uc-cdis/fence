#!/bin/bash

sed -i.bak -e 's/WSGIDaemonProcess fence processes=1 threads=3/WSGIDaemonProcess fence processes='${WSGI_PROCESSES:-1}' threads='${WSGI_THREADS:-3}'/g' /etc/apache2/sites-available/fence.conf
cd /var/www/fence; sudo -u www-data python wsgi.py
/usr/sbin/apache2ctl -D FOREGROUND
