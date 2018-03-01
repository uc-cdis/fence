from fence.auth import build_redirect_url


def test_redirect_url():
    assert build_redirect_url('', '/') == '/'
    assert build_redirect_url('host.domain', '/fred') == 'https://host.domain/fred'
    assert build_redirect_url('http://host.domain', '/a/b/c') == 'http://host.domain/a/b/c'


def test_logout_if_anonymous(app, client, monkeypatch):
    monkeypatch.setitem(app.config, 'MOCK_AUTH', False)
    r = client.get('/logout')
    assert r.status_code == 401


def test_logout(client):
    # login mocked uesr
    r = client.get('/user/')
    r = client.get('/logout')
    assert r.status_code == 302
