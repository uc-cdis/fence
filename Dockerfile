# To run: docker run -d -v /path/to/fence-config.yaml:/var/www/fence/fence-config.yaml --name=fence -p 80:80 fence
# To check running container: docker exec -it fence /bin/bash

FROM quay.io/cdis/python-nginx:feat_python-base-buffer

ENV appname=fence

RUN apk update \
    && apk add postgresql-libs postgresql-dev libffi-dev libressl-dev \
    && apk add linux-headers musl-dev gcc \
    && apk add curl bash git vim make

COPY . /$appname
COPY ./deployment/uwsgi/uwsgi.ini /etc/uwsgi/uwsgi.ini
COPY ./deployment/uwsgi/wsgi.py /$appname/wsgi.py
WORKDIR /$appname

RUN python -m pip install --upgrade pip \
    && python -m pip install --upgrade setuptools \
    && pip install -r requirements.txt

RUN mkdir -p /var/www/$appname \
    && mkdir -p /var/www/.cache/Python-Eggs/ \
    && mkdir /run/nginx/ \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log \
    && chown nginx -R /var/www/.cache/Python-Eggs/ \
    && chown nginx /var/www/$appname

RUN apk update && apk add openssh && apk add libmcrypt-dev

#
# libmhash is required by mcrypt - below - no apk package available
#
RUN (cd /tmp \
  && wget -O mhash.tar.gz https://sourceforge.net/projects/mhash/files/mhash/0.9.9.9/mhash-0.9.9.9.tar.gz/download \
  && tar xvfz mhash.tar.gz \
  && cd mhash-0.9.9.9 \
  && ./configure && make && make install \
  && /bin/rm -rf /tmp/*)

#
# mcrypt is required to decrypt dbgap user files - see fence/sync/sync_users.py
#
RUN (cd /tmp \
  && wget -O mcrypt.tar.gz https://sourceforge.net/projects/mcrypt/files/MCrypt/Production/mcrypt-2.6.4.tar.gz/download \
  && tar xvfz mcrypt.tar.gz \
  && cd mcrypt-2.6.4 \
  && ./configure && make && make install \
  && /bin/rm -rf /tmp/*)
EXPOSE 80

RUN COMMIT=`git rev-parse HEAD` && echo "COMMIT=\"${COMMIT}\"" >$appname/version_data.py \
    && VERSION=`git describe --always --tags` && echo "VERSION=\"${VERSION}\"" >>$appname/version_data.py \
    && python setup.py develop

WORKDIR /var/www/$appname

CMD ["sh","-c","bash /fence/dockerrun.bash && /dockerrun.sh"]
