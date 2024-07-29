# run nginx and gunicorn
nginx -g 'daemon off;'
gunicorn -c deployment/wsgi/gunicorn.conf.py
