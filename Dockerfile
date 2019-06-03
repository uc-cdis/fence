# To run: docker run -d -v /path/to/fence-config.yaml:/var/www/fence/fence-config.yaml --name=fence -p 80:80 fence
# To check running container: docker exec -it fence /bin/bash

FROM quay.io/cdis/py27base:pybase2-1.0.1

RUN mkdir /var/www/fence \
	&& chown www-data /var/www/fence

COPY . /fence
COPY ./deployment/uwsgi/uwsgi.ini /etc/uwsgi/uwsgi.ini

WORKDIR /fence

RUN python -m pip install -r requirements.txt
RUN ln -s /fence/wsgi.py /var/www/fence/wsgi.py
RUN COMMIT=`git rev-parse HEAD` && echo "COMMIT=\"${COMMIT}\"" >fence/version_data.py
RUN VERSION=`git describe --always --tags` && echo "VERSION=\"${VERSION}\"" >>fence/version_data.py


EXPOSE 80

WORKDIR /var/www/fence

CMD ["sh","-c","bash /fence/dockerrun.bash && /dockerrun.sh"]
