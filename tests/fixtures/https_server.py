"""Owned loopback HTTPS fixture. All credential values are synthetic."""
import json
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

counts=Counter()
observed=[]
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self): self.handle_request()
    def do_POST(self): self.handle_request()
    def do_PUT(self): self.handle_request()
    def do_PATCH(self): self.handle_request()
    def do_DELETE(self): self.handle_request()
    def handle_request(self):
        path=urlsplit(self.path).path
        counts[path]+=1
        body=self.rfile.read(int(self.headers.get('Content-Length',0)))
        if path=='/stats':
            return self.reply(200,{'counts':dict(counts),'observed':observed})
        observed.append({'path':path,'method':self.command,'headers':dict(self.headers),'body':body.decode(errors='replace')})
        if path=='/oauth/token':
            form=parse_qs(body.decode())
            if form.get('grant_type')!=['client_credentials'] or form.get('scope')!=['a2a']:
                return self.reply(400,{'error':'bad wire format'})
            return self.reply(200,{'access_token':'fixture-access','agent_secret_token':'fixture-pass','expires_in':7200,'agent_secret_token_expires_in':60})
        if path=='/oauth/agent/introspect':
            form=parse_qs(body.decode())
            if self.headers.get('Authorization')!='Bearer fixture-access': return self.reply(401,{})
            valid=form.get('agent_secret_token')==['fixture-pass']
            return self.reply(200,{'active':valid,'agent_id':form.get('agent_user_id',[''])[0], 'scopes':'a2a','expires_at':time.time()+30})
        if path=='/redirect': return self.reply(307,{}, {'Location':f'https://localhost:{self.server.server_port}/leak'})
        if path=='/write': return self.reply(503,{'error':'SECRET_CANARY'})
        if path=='/retry' and counts[path]==1: return self.reply(503,{}, {'Retry-After':'0'})
        if path=='/large': return self.reply(200,{'data':'x'*(5*1024*1024)})
        if path=='/slow':
            self.send_response(200);self.send_header('Content-Type','text/plain');self.end_headers()
            try:
                for _ in range(100): self.wfile.write(b'x');self.wfile.flush();time.sleep(.05)
            except (BrokenPipeError,ConnectionResetError,ssl.SSLError): pass
            return
        return self.reply(200,{'ok':True})
    def reply(self,status,data,headers=None):
        raw=json.dumps(data).encode()
        self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers()
        try:self.wfile.write(raw)
        except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass

with tempfile.TemporaryDirectory(prefix='sentinel-sdk-tls-') as d:
    root=Path(d);cert=root/'cert.pem';key=root/'key.pem'
    config=root/'openssl.cnf'
    config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n')
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-config',str(config),'-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    print(json.dumps({'url':f'https://localhost:{server.server_port}','cert':str(cert)}),flush=True)
    sys.stdin.read()
    server.shutdown();server.server_close()
