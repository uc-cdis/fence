# To run: docker run --rm -d -v /path/to/fence-config.yaml:/var/www/fence/fence-config.yaml --name=fence -p 80:80 fence
# To check running container: docker exec -it fence /bin/bash

FROM quay.io/cdis/python-nginx:pybase3-1.6.2

ENV appname=fence

RUN pip install --upgrade pip
RUN apk add --update \
    postgresql-libs postgresql-dev libffi-dev libressl-dev \
    linux-headers musl-dev gcc g++ logrotate \
    curl bash git vim make lftp \
    openssh libmcrypt-dev

RUN mkdir -p /var/www/$appname \
    && mkdir -p /var/www/.cache/Python-Eggs/ \
    && mkdir /run/nginx/ \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log \
    && chown nginx -R /var/www/.cache/Python-Eggs/ \
    && chown nginx /var/www/$appname

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

# aws cli v2 - needed for storing files in s3 during usersync k8s job
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && /bin/rm -rf awscliv2.zip ./aws

# install poetry
RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python

COPY . /$appname
COPY ./deployment/uwsgi/uwsgi.ini /etc/uwsgi/uwsgi.ini
COPY ./deployment/uwsgi/wsgi.py /$appname/wsgi.py
COPY clear_prometheus_multiproc /$appname/clear_prometheus_multiproc
WORKDIR /$appname

# cache so that poetry install will run if these files change
COPY poetry.lock pyproject.toml /$appname/

# install Fence and dependencies via poetry
RUN source $HOME/.poetry/env \
    && poetry config virtualenvs.create false \
    && poetry install -vv --no-dev --no-interaction \
    && poetry show -v

RUN COMMIT=`git rev-parse HEAD` && echo "COMMIT=\"${COMMIT}\"" >$appname/version_data.py \
    && VERSION=`git describe --always --tags` && echo "VERSION=\"${VERSION}\"" >>$appname/version_data.py

WORKDIR /var/www/$appname

CMD ["sh","-c","bash /fence/dockerrun.bash && /dockerrun.sh"]
