import flask

from fence.models import Client


def query_client(client_id):
    with flask.current_app.db.session as session:
        return session.query(Client).filter_by(client_id=client_id).first()


def authenticate_public_client(query_client, request):
    print()
