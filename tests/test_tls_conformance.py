"""Actual TLS transport qualification, using only an owned loopback server."""
import json
import subprocess
import sys
import time
from pathlib import Path
import pytest
import requests
from traylinx_auth_client import TraylinxAuthClient
from traylinx_auth_client.exceptions import TraylinxAuthError, NetworkError

ID='12345678-1234-1234-1234-123456789abc'
@pytest.fixture(scope='module')
def fixture():
    p=subprocess.Popen([sys.executable,str(Path(__file__).parent/'fixtures/https_server.py')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    try:
        info=json.loads(p.stdout.readline())
        yield info
    finally:
        p.stdin.close();p.wait(timeout=10)

@pytest.fixture
def client(fixture):
    with TraylinxAuthClient('fixture-client','synthetic-secret-123',fixture['url'],ID,timeout=1,max_retries=1,retry_delay=.1) as c:
        c._session.verify=fixture['cert']
        yield c

def stats(fixture):
    with requests.Session() as s:
        s.trust_env=False
        return s.get(fixture['url']+'/stats',verify=fixture['cert'],timeout=3).json()

def test_tls_exchange_and_introspection(client,fixture):
    assert client.get_agent_request_headers()=={'X-Agent-Secret-Token':'fixture-pass','X-Agent-User-Id':ID}
    assert client.validate_token('fixture-pass',ID)
    assert not client.validate_token('invalid',ID)
    calls=stats(fixture)['observed']
    call=next(c for c in calls if c['path']=='/oauth/agent/introspect')
    assert call['headers']['Authorization']=='Bearer fixture-access'
    assert 'agent_user_id='+ID in call['body']

def test_redirect_never_receives_credentials(client,fixture):
    with pytest.raises(TraylinxAuthError):client.rpc_call('work',{},fixture['url']+'/redirect',True)
    assert '/leak' not in stats(fixture)['counts']

def test_writes_not_replayed(client,fixture):
    with pytest.raises(TraylinxAuthError) as err: client.rpc_call('work',{},fixture['url']+'/write',True)
    assert 'SECRET_CANARY' not in str(err.value)
    assert stats(fixture)['counts']['/write']==1

def test_get_retry(client,fixture):
    assert client._session.get(fixture['url']+'/retry').json()=={'ok':True}
    assert stats(fixture)['counts']['/retry']==2

def test_size_limit(client,fixture):
    with pytest.raises(NetworkError): client._session.get(fixture['url']+'/large',response_limit=65536)

def test_slow_drip_deadline(client,fixture):
    start=time.monotonic()
    with pytest.raises(NetworkError):client.rpc_call('work',{},fixture['url']+'/slow',True)
    assert time.monotonic()-start<3

def test_untrusted_certificate_rejected(fixture):
    with TraylinxAuthClient('fixture-client','synthetic-secret-123',fixture['url'],ID,timeout=1) as c:
        with pytest.raises(TraylinxAuthError):c.get_access_token()
