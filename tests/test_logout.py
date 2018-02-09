from fence.auth import build_redirect_url

def test_redirect_url():
  assert build_redirect_url('', '/') == '/'
  assert build_redirect_url('host.domain', '/fred') == 'https://host.domain/fred'
  assert build_redirect_url('http://host.domain', '/a/b/c') == 'http://host.domain/a/b/c'

