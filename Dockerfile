# To build: docker build -t fence:latest .
# To run interactive:
#   docker run -v ~/.gen3/fence/fence-config.yaml:/var/www/fence/fence-config.yaml -v ./keys/:/fence/keys/ fence:latest
# To check running container do: docker exec -it CONTAINER bash

ARG AZLINUX_BASE_VERSION=3.13-pythonnginx

# ------ Base stage ------
FROM quay.io/cdis/amazonlinux-base:${AZLINUX_BASE_VERSION} AS base
# Comment this in, and comment out the line above, if quay is down
# FROM 707767160287.dkr.ecr.us-east-1.amazonaws.com/gen3/python-nginx-al:${AZLINUX_BASE_VERSION} as base

ENV appname=fence

WORKDIR /${appname}

RUN chown -R gen3:gen3 /${appname}

USER root
RUN chown -R gen3:gen3 /venv/
USER gen3
# ------ Builder stage ------
FROM base AS builder

USER gen3

# copy ONLY poetry artifact, install the dependencies but not the app;
# this will make sure that the dependencies are cached
COPY poetry.lock pyproject.toml /${appname}/
RUN poetry install -vv --no-root --only main --no-interaction

# Move app files into working directory
COPY --chown=gen3:gen3 . /$appname
COPY --chown=gen3:gen3 ./deployment/wsgi/wsgi.py /$appname/wsgi.py

# install the app
RUN poetry install --without dev --no-interaction

# Setup version info
RUN git config --global --add safe.directory ${appname} && COMMIT=`git rev-parse HEAD` && echo "COMMIT=\"${COMMIT}\"" > $appname/version_data.py \
    && VERSION=`git describe --always --tags` && echo "VERSION=\"${VERSION}\"" >> $appname/version_data.py



# ------ Final stage ------
FROM base

# Import global virtualenv from builder
COPY --from=builder /venv /venv
ENV PATH="/venv/bin:$PATH"

# Switching to root user to run dnf upgrades
USER root
# Install ccrypt to decrypt dbgap telmetry files
RUN echo "Upgrading dnf"; \
    dnf upgrade -y; \
    echo "Installing Packages"; \
    dnf install -y \
        libxcrypt-compat-4.4.33 \
        libpq-15.0 \
        gcc \
        diffutils \
        tar xz; \
    echo "Installing RPM"; \
    rpm -i https://ccrypt.sourceforge.net/download/1.11/ccrypt-1.11-1.src.rpm && \
    cd /root/rpmbuild/SOURCES/ && \
    tar -zxf ccrypt-1.11.tar.gz && cd ccrypt-1.11 && ./configure --disable-libcrypt && make install && make check;
RUN mkdir -p /var/www/fence && chown -R gen3:gen3 /var/www/fence
# This `sed` command was previously executed in the usersync CronJob as it is required for DBGaP sync:
# https://github.com/uc-cdis/gen3-helm/blob/e5f49978ac16364374252b8dfd9cfa28df4baf9a/helm/fence/templates/usersync-cron.yaml#L249C17-L249C192
#
# The logic has been moved into the Dockerfile because it requires root privileges,
# while the usersync CronJob now runs as a non-root user.
RUN sed -i 's/KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,/KexAlgorithms ecdh-sha2-nistp256,/g' /etc/crypto-policies/back-ends/openssh.config

COPY --chown=gen3:gen3 --from=builder /$appname /$appname

# OpenShift runs containers with an arbitrary UID in the root group (GID 0),
# so everything the process writes to must be group-writable by GID 0.
# nginx listens on 8080 (unprivileged) using a config without the `user` directive.
USER root
COPY deployment/nginx/nginx.conf /etc/nginx/nginx.conf
# Drop nginx's file capability (cap_net_bind_service); restricted SCCs drop all caps
# and the binary would otherwise fail to exec. Not needed on port 8080.
RUN setcap -r /usr/sbin/nginx && \
    mkdir -p /tmp/nginx && \
    chgrp -R 0 /fence /var/lib/nginx /var/log/nginx /tmp/nginx /var/www/fence && \
    chmod -R g=u /fence /var/lib/nginx /var/log/nginx /tmp/nginx /var/www/fence && \
    chmod g+rx /etc/nginx/nginx.conf

# Arbitrary UIDs have no home dir; gunicorn writes its control socket under $HOME
ENV HOME=/tmp

EXPOSE 8080

# Non-root user; OpenShift will override the UID but keep GID 0
USER 1000:0

CMD ["/bin/bash", "-c", "/fence/dockerrun.bash"]
