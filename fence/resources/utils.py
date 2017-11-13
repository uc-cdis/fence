from errors import InternalError
import settings
from django.shortcuts import redirect
import logging

logger = logging.getLogger(__name__)


def redirect_to_next(request):
    return redirect(request.session.get('next', settings.ROOT_PATH))


def handle_request(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.exception("internal error")
            raise InternalError(e)
    return wrapper
