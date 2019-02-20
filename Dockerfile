# To run: docker run -d -v /path/to/fence-config.yaml:/var/www/fence/fence-config.yaml --name=fence -p 80:80 fence
# To check running container: docker exec -it fence /bin/bash

FROM ubuntu:16.04
# image for sftp & ssh protocols
FROM atmoz/sftp:debian-jessie

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 \
    build-essential \
    curl \
    git \
    # for ftp
    lftp \
    # for decryption dbgap files
    mcrypt \
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
    && pip install pip==9.0.3 \
    && pip install --upgrade setuptools \
    && mkdir /var/www/fence \
    && mkdir -p /var/www/.cache/Python-Eggs/ \
    && chown www-data -R /var/www/.cache/Python-Eggs/

COPY . /fence
WORKDIR /fence
COPY deployment/fence.conf /etc/apache2/sites-available/fence.conf

#
# Custom apache24 logging - see http://www.loadbalancer.org/blog/apache-and-x-forwarded-for-headers/
#
RUN ln -s /fence/wsgi.py /var/www/fence/wsgi.py \
    && pip install -r requirements.txt \
    && COMMIT=`git rev-parse HEAD` && echo "COMMIT=\"${COMMIT}\"" >fence/version_data.py \
    && VERSION=`git describe --always --tags` && echo "VERSION=\"${VERSION}\"" >>fence/version_data.py \
    && python setup.py develop \
    && a2dissite 000-default \
    && a2ensite fence \
    && a2enmod reqtimeout \
    && ln -sf /dev/stdout /var/log/apache2/access.log \
    && ln -sf /dev/stderr /var/log/apache2/error.log

EXPOSE 80
WORKDIR /var/www/fence/

CMD bash /fence/dockerrun.bash
