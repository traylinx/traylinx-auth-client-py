"""Security regressions using synthetic credentials; no external services."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading
import time
import traceback
from unittest.mock import Mock, patch
import pytest
import requests
from fastapi import HTTPException, Request
from traylinx_auth_client import TraylinxAuthClient
from traylinx_auth_client.exceptions import TraylinxAuthError, AuthenticationError, ValidationError, NetworkError
from traylinx_auth_client.security import destination, credentials_from, outbound_options, token_state, valid_introspection
from traylinx_auth_client.transport import SecureSession
from traylinx_auth_client.main import require_a2a_auth, require_dual_auth, make_a2a_request, a2a_request

ID = '12345678-1234-1234-1234-123456789abc'
def client(**kwargs):
    return TraylinxAuthClient('fixture-client','synthetic-secret-123','https://sentinel.example',ID,**kwargs)
def tokens(**kwargs):
    return dict(access_token='synthetic-access',agent_secret_token='synthetic-pass',expires_in=7200,**kwargs)
def response(data=None, status=200):
    r=Mock(status_code=status)
    r.json.return_value=data
    return r

@pytest.mark.parametrize('url',['http://example.com','https://u:SECRET@example.com','https://example.com/#SECRET','https://example.com\\@evil.test','https://example.com/\nsecret','file:///tmp/a','https:example.com',None])
def test_unsafe_destinations(url):
    with pytest.raises(ValidationError): destination(url)

@pytest.mark.parametrize('options',[{'headers':{'Authorization':'secret'}},{'headers':{'X-Agent-User-Id':'wrong'}},{'headers':{'Host':'evil'}},{'allow_redirects':True},{'verify':False},{'auth':('u','p')},{'timeout':0},{'timeout':float('inf')},{'timeout':True},{'headers':{'A':'x','a':'y'}}])
def test_unsafe_options(options):
    with pytest.raises(ValidationError): outbound_options(options)

def test_options_immutable():
    opts={'headers':{'X-Correlation-Id':'test'},'timeout':2}
    safe=outbound_options(opts)
    safe['headers']['changed']='yes'
    assert opts=={'headers':{'X-Correlation-Id':'test'},'timeout':2}

@pytest.mark.parametrize('headers',[
    {'Authorization':'Bearer a','X-Agent-Secret-Token':'b','X-Agent-User-Id':ID},
    {'Authorization':'Bearer a','authorization':'Bearer b','X-Agent-User-Id':ID},
    {'Authorization':'Bearer a, Bearer b','X-Agent-User-Id':ID},
    {'X-Agent-Secret-Token':['a'],'X-Agent-User-Id':ID},
    {'X-Agent-Secret-Token':'a','X-Agent-User-Id':'x\nInjected:yes'}, None])
def test_ambiguous_headers(headers): assert credentials_from(headers) is None

@pytest.mark.parametrize('expiry',[0,-1,None,True,'3600',float('inf'),float('nan')])
def test_malformed_token_lifetimes(expiry):
    data=tokens();data['expires_in']=expiry
    with pytest.raises(AuthenticationError): token_state(data,time.time())

def test_two_lifetimes_and_expiry_during_exchange():
    now=time.time()
    state=token_state(tokens(agent_secret_token_expires_in=60),now)
    assert state[3]<state[2]
    assert token_state(tokens(),now)[3]==0
    with pytest.raises(AuthenticationError): token_state(tokens(),now-8000)
    with pytest.raises(AuthenticationError): token_state(tokens(agent_secret_token_expires_in=-1),now)

@pytest.mark.parametrize('option',[{'agent_token_ttl_seconds':True},{'agent_token_ttl_seconds':float('inf')},{'refresh_skew_seconds':-1},{'refresh_skew_seconds':True}])
def test_config_rejects_invalid_lifetimes(option):
    with pytest.raises(ValidationError): client(**option)

def test_metadata_identity_scope_expiry():
    data=dict(active=True,agent_id=ID,scopes='a2a',expires_at=time.time()+60)
    assert valid_introspection(data,ID)
    for change in [dict(active='true'),dict(agent_id='wrong'),dict(expires_at=0),dict(expires_at=True),dict(scopes='other'),dict(is_active=False)]:
        assert not valid_introspection(dict(data,**change),ID)
    c=client();c.get_access_token=Mock(return_value='service-access')
    c._session.post=Mock(return_value=response(dict(data,private='do not return')))
    assert c.introspect_token('pass',ID)==data
    assert c.validate_token('pass',ID) is True
    assert c.introspect_token('',ID)=={'active':False}
    c._session.post.return_value=response(status=400)
    assert c.validate_token('pass',ID) is False
    c._session.post.return_value=response({'active':'true'})
    assert c.validate_token('pass',ID) is False
    c._session.post.return_value=response()
    c._session.post.return_value.json.side_effect=ValueError('SECRET_CANARY')
    with pytest.raises(AuthenticationError): c.introspect_token('pass',ID)


def test_singleflight_100_waiters():
    c=client();barrier=threading.Barrier(100)
    def fetch(*args,**kwargs):
        time.sleep(.15)
        return response(tokens())
    c._session.post=Mock(side_effect=fetch)
    def acquire(_):
        barrier.wait();return c.get_agent_secret_token()
    with ThreadPoolExecutor(max_workers=100) as pool:
        results=list(pool.map(acquire,range(100)))
    assert set(results)=={'synthetic-pass'}
    assert c._session.post.call_count==1
    c.get_agent_secret_token() # Unknown AST TTL cannot be reused sequentially.
    assert c._session.post.call_count==2


def test_cache_disabled_pair_and_failure_recovery():
    c=client(cache_tokens=False)
    c._session.post=Mock(side_effect=[response(tokens()),response({}),response(tokens())])
    h=c.get_request_headers()
    assert h['Authorization']=='Bearer synthetic-access'
    assert c._session.post.call_count==1
    with pytest.raises(AuthenticationError): c.get_request_headers()
    assert c._access_token is None and c._agent_secret_token is None
    assert c.get_agent_secret_token()=='synthetic-pass'


def test_known_ttl_reuses_and_early_refresh():
    c=client(agent_token_ttl_seconds=60)
    c._session.post=Mock(return_value=response(tokens()))
    c.get_agent_secret_token();c.get_request_headers();c.get_agent_secret_token()
    assert c._session.post.call_count==1
    c._agent_token_expiration=time.time()-1
    c.get_agent_secret_token()
    assert c._session.post.call_count==2


def test_cross_origin_access_rejected_before_token_mint():
    c=client();c.get_access_token=Mock()
    with pytest.raises(ValidationError): c.rpc_call('work',{},'https://other.example/rpc',False)
    c.get_access_token.assert_not_called()


def test_redaction_including_exception_traceback():
    c=client()
    c._session.post=Mock(side_effect=requests.ConnectionError('SECRET_CANARY'))
    try: c.get_access_token()
    except NetworkError:
        assert 'SECRET_CANARY' not in traceback.format_exc()
    for error in [Exception('SECRET_CANARY'), requests.HTTPError('SECRET_CANARY',response=Mock(status_code=400))]:
        with pytest.raises(TraylinxAuthError) as caught: c._handle_request_error(error)
        assert 'SECRET_CANARY' not in str(caught.value)

@pytest.mark.asyncio
@pytest.mark.parametrize('decorator,validator',[(require_a2a_auth,'validate_a2a_request'),(require_dual_auth,'validate_dual_auth_request')])
async def test_async_validation_off_loop_and_downstream_preserved(decorator,validator):
    main_thread=threading.get_ident();seen=[]
    def validate(h):
        seen.append(threading.get_ident());time.sleep(.05);return True
    request=Request({'type':'http','headers':[]})
    @decorator
    async def endpoint(request):
        raise HTTPException(418,'downstream')
    with patch('traylinx_auth_client.main.'+validator,side_effect=validate):
        with pytest.raises(HTTPException) as err: await endpoint(request)
        assert err.value.status_code==418
    assert seen and seen[0]!=main_thread
    with pytest.raises(HTTPException) as err: await endpoint()
    assert err.value.status_code==500
    with patch('traylinx_auth_client.main.'+validator,side_effect=RuntimeError('SECRET_CANARY')):
        with pytest.raises(HTTPException) as err: await endpoint(request)
        assert err.value.status_code==503 and 'SECRET' not in err.value.detail

@pytest.mark.parametrize('method',['POST','PUT','PATCH','DELETE','GET'])
def test_transport_write_no_retry_and_read_bounded_retry(requests_mock,method):
    requests_mock.register_uri(method,'https://fixture.example/work',[{'status_code':503},{'json':{'ok':True}}])
    with SecureSession(timeout=3,max_retries=1,retry_delay=.01) as s:
        r=s.request(method,'https://fixture.example/work')
    assert requests_mock.call_count==(2 if method=='GET' else 1)
    assert r.status_code==(200 if method=='GET' else 503)

@pytest.mark.parametrize('options',[{'verify':False},{'allow_redirects':True},{'stream':True},{'data':object()},{'json':{'bad':object()}},{'data':'x'*(4*1024*1024+1)}])
def test_transport_rejects_unsafe_options(options):
    with SecureSession() as s, pytest.raises(ValidationError): s.post('https://fixture.example',**options)

def test_transport_redirect_size_retry_after_and_cookie_isolation(requests_mock):
    with SecureSession(timeout=1,max_retries=2) as s:
        requests_mock.get('https://fixture.example/redirect',status_code=302,headers={'Location':'https://evil.example'})
        with pytest.raises(NetworkError,match='Redirect'): s.get('https://fixture.example/redirect')
        requests_mock.get('https://fixture.example/large',content=b'x'*20)
        with pytest.raises(NetworkError,match='too large'): s.get('https://fixture.example/large',response_limit=5)
        requests_mock.get('https://fixture.example/retry',status_code=429,headers={'Retry-After':'99999'})
        assert s.get('https://fixture.example/retry').status_code==429
        s.cookies.set('private','secret')
        requests_mock.get('https://fixture.example/ok',json={'ok':True})
        s.get('https://fixture.example/ok')
        assert not requests_mock.last_request.headers.get('Cookie')
        assert not s.cookies


def test_helpers_validate_before_secrets_and_sanitize_errors():
    with patch('traylinx_auth_client.main.get_agent_request_headers') as getter:
        with pytest.raises(ValidationError): make_a2a_request('GET','http://unsafe.example')
        @a2a_request('GET','https://safe.example',headers={'Authorization':'secret'})
        def unsafe(): raise AssertionError('must not execute')
        with pytest.raises(ValidationError): unsafe()
        getter.assert_not_called()
    c=client()
    with patch('traylinx_auth_client.main.get_default_client',return_value=c), patch.object(c,'get_agent_request_headers',return_value={}), patch.object(SecureSession,'request',side_effect=requests.Timeout('SECRET_CANARY')):
        with pytest.raises(NetworkError): make_a2a_request('GET','https://safe.example')


def test_p2p_legacy_surface_remains_usable():
    c=client();c.get_access_token=Mock(return_value='synthetic-access')
    c._session.get=Mock(return_value=response({'challenge':'challenge'}))
    assert c.get_p2p_challenge('a'*32)=='challenge'
    c._session.get.side_effect=requests.ConnectionError('canary')
    with pytest.raises(NetworkError): c.get_p2p_challenge('a'*32)
    args=dict(peer_id='a'*32,public_key='key',signature='sig',challenge='challenge')
    for field in args:
        with pytest.raises(ValidationError): c.certify_p2p_identity(**dict(args,**{field:''}))
    c._session.post=Mock(return_value=response({'certificate':'cert','expires_at':'date'}))
    assert c.certify_p2p_identity(**args)['certificate']=='cert'
    for status in (401,409):
        c._session.post.return_value=response(status=status)
        with pytest.raises(AuthenticationError): c.certify_p2p_identity(**args)
    c._session.post.return_value=response({})
    with pytest.raises(AuthenticationError): c.certify_p2p_identity(**args)
    c._session.post.return_value=response();c._session.post.return_value.json.side_effect=ValueError()
    with pytest.raises(AuthenticationError): c.certify_p2p_identity(**args)
    c._session.post.side_effect=requests.ConnectionError('canary')
    with pytest.raises(NetworkError): c.certify_p2p_identity(**args)
    assert c.get_p2p_certificate_status('a'*32) is None

def test_singleflight_failure_and_explicit_recovery():
    c=client();barrier=threading.Barrier(20)
    def fail(*args,**kwargs):
        time.sleep(.15)
        raise requests.ConnectionError('SECRET_CANARY')
    c._session.post=Mock(side_effect=fail)
    def acquire(_):
        barrier.wait()
        with pytest.raises(NetworkError) as err: c.get_agent_secret_token()
        return str(err.value)
    with ThreadPoolExecutor(max_workers=20) as pool: results=list(pool.map(acquire,range(20)))
    assert c._session.post.call_count==1
    assert all('SECRET_CANARY' not in result for result in results)
    c._session.post=Mock(return_value=response(tokens()))
    assert c.get_agent_secret_token()=='synthetic-pass'
