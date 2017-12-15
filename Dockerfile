# To run: docker run -d -v /path/to/local_settings.py:/var/www/fence/local_settings.py --name=fence -p 80:80 fence
# To check running container: docker exec -it fence /bin/bash

FROM ubuntu:16.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    build-essential \
    curl \
    git \
    libapache2-mod-wsgi \
    # dependency for cryptography
    libffi-dev \
    # dependency for pyscopg2 - which is dependency for sqlalchemy postgres engine
    libpq-dev \
    # dependency for cryptography
    libssl-dev \
    python2.7 \
    python-dev \
    python-pip \
    python-setuptools \
    vim \
    && pip install --upgrade pip \
    && pip install --upgrade setuptools \
    && mkdir /var/www/fence \
    && mkdir -p /var/www/.cache/Python-Eggs/ \
    && chown www-data -R /var/www/.cache/Python-Eggs/

COPY . /fence
WORKDIR /fence
RUN ln -s /fence/wsgi.py /var/www/fence/wsgi.py \
    && python setup.py install \
    && echo '<VirtualHost *:80>\n\
    WSGIDaemonProcess /fence processes=1 threads=1 python-path=/var/www/fence/:/fence/:/usr/bin/python\n\
    WSGIScriptAlias / /var/www/fence/wsgi.py\n\
    WSGIPassAuthorization On\n\
    <Directory "/var/www/fence/">\n\
        WSGIProcessGroup /fence\n\
        WSGIApplicationGroup %{GLOBAL}\n\
        Options +ExecCGI\n\
        Order deny,allow\n\
        Allow from all\n\
    </Directory>\n\
    ErrorLog ${APACHE_LOG_DIR}/error.log\n\
    LogLevel warn\n\
    CustomLog ${APACHE_LOG_DIR}/access.log combined\n\
</VirtualHost>\n'\
>> /etc/apache2/sites-available/fence.conf \
    && a2dissite 000-default \
    && a2ensite fence \
    && ln -sf /dev/stdout /var/log/apache2/access.log \
    && ln -sf /dev/stderr /var/log/apache2/error.log

EXPOSE 80
WORKDIR /var/www/fence/

CMD rm -f /var/run/apache2/apache2.pid && /usr/sbin/apache2ctl -D FOREGROUND
