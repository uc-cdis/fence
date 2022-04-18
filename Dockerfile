# To run: docker run --rm -d -v /path/to/fence-config.yaml:/var/www/fence/fence-config.yaml --name=fence -p 80:80 fence
# To check running container do: docker exec -it fence /bin/bash

FROM quay.io/cdis/python:python3.6-buster-pybase3-3.0.2

ENV appname=fence

RUN pip install --upgrade pip
RUN pip install --upgrade poetry
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl bash git vim \
    libmcrypt4 libmhash2 mcrypt \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/

RUN mkdir -p /var/www/$appname \
    && mkdir -p /var/www/.cache/Python-Eggs/ \
    && mkdir /run/nginx/ \
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log \
    && chown nginx -R /var/www/.cache/Python-Eggs/ \
    && chown nginx /var/www/$appname

# aws cli v2 - needed for storing files in s3 during usersync k8s job
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && /bin/rm -rf awscliv2.zip ./aws

WORKDIR /$appname

# copy ONLY poetry artifact, install the dependencies but not fence
# this will make sure than the dependencies is cached
COPY poetry.lock pyproject.toml /$appname/
RUN poetry config virtualenvs.create false \
    && poetry install -vv --no-root --no-dev --no-interaction \
    && poetry show -v

# copy source code ONLY after installing dependencies
COPY . /$appname
COPY ./deployment/uwsgi/uwsgi.ini /etc/uwsgi/uwsgi.ini
COPY ./deployment/uwsgi/wsgi.py /$appname/wsgi.py
COPY clear_prometheus_multiproc /$appname/clear_prometheus_multiproc

# install fence
RUN poetry config virtualenvs.create false \
    && poetry install -vv --no-dev --no-interaction \
    && poetry show -v

RUN COMMIT=`git rev-parse HEAD` && echo "COMMIT=\"${COMMIT}\"" >$appname/version_data.py \
    && VERSION=`git describe --always --tags` && echo "VERSION=\"${VERSION}\"" >>$appname/version_data.py

WORKDIR /var/www/$appname

CMD ["sh","-c","bash /fence/dockerrun.bash && /dockerrun.sh"]
