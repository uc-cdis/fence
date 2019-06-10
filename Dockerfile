# To run: docker run -d -v /path/to/fence-config.yaml:/var/www/fence/fence-config.yaml --name=fence -p 80:80 fence
# To check running container: docker exec -it fence /bin/bash

FROM quay.io/cdis/py27base:pybase2-1.0.2

RUN mkdir /var/www/fence \
    && chown www-data /var/www/fence

COPY . /fence
COPY ./deployment/uwsgi/uwsgi.ini /etc/uwsgi/uwsgi.ini

WORKDIR /fence

RUN pip install --upgrade pip \
  && python -m pip install -r requirements.txt
RUN ln -s /fence/wsgi.py /var/www/fence/wsgi.py
RUN COMMIT=`git rev-parse HEAD` && echo "COMMIT=\"${COMMIT}\"" >fence/version_data.py
RUN VERSION=`git describe --always --tags` && echo "VERSION=\"${VERSION}\"" >>fence/version_data.py
RUN python setup.py develop

RUN apk update && apk add openssh && apk add libmcrypt-dev
RUN (cd /tmp \
  && wget -O mhash.tar.gz https://sourceforge.net/projects/mhash/files/mhash/0.9.9.9/mhash-0.9.9.9.tar.gz/download \
  && tar xvfz mhash.tar.gz \
  && cd mhash-0.9.9.9 \
  && ./configure && make && make install \
  && /bin/rm -rf /tmp/*)
RUN (cd /tmp \
  && wget -O mcrypt.tar.gz https://sourceforge.net/projects/mcrypt/files/MCrypt/Production/mcrypt-2.6.4.tar.gz/download \
  && tar xvfz mcrypt.tar.gz \
  && cd mcrypt-2.6.4 \
  && ./configure && make && make install \
  && /bin/rm -rf /tmp/*)
EXPOSE 80

WORKDIR /var/www/fence

CMD ["sh","-c","bash /fence/dockerrun.bash && /dockerrun.sh"]