import flask
from flask_sqlalchemy_session import current_session
from fence.auth import login_user
from fence.models import User, IdentityProvider

def test_login_user_in_current_session(db_session):
    email = "testuser@gmail.com"
    provider = "Test Provider"

    test_user = User(username=email, is_admin=False)
    db_session.add(test_user)
    db_session.commit()
    user_id = str(test_user.id)

    login_user(flask.request, email, provider)
    assert flask.session['username'] == email
    assert flask.session['provider'] == provider
    assert flask.session['user_id'] == user_id
    assert flask.g.user == test_user

def test_login_user_not_in_current_session(db_session):
    email = "testuser@gmail.com"
    provider = "Test Provider"

    login_user(flask.request, email, provider)
    test_user = db_session.query(
        User).filter(User.username == email.lower()).first()

    assert flask.session['username'] == email
    assert flask.session['provider'] == provider
    assert flask.session['user_id'] == str(test_user.id)
    assert flask.g.user == test_user
