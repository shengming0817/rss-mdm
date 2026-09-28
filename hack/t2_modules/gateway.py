"""Run the actual login rate profile against a scoped local content server, not a mock Identity."""
import http.client
import socket
from pathlib import Path
from t2_processes import subprocess
import tempfile
import time
import uuid
import json
import sys
from build_run import require_lease
ROOT=Path(__file__).resolve().parents[2]

def verify(context):
    # Only TLS/file/listener locations are adapted for this loopback protocol seam.
    # The source-key, budget, burst, error and location rules are the production file.
    config=(ROOT/'deployment/nginx.conf').read_text()
    config=config.replace('listen 443 ssl;','listen 8080;').replace('ssl_certificate /private/mdm-tls.crt;','').replace('ssl_certificate_key /private/mdm-tls.key;','')
    config=config.replace('server 127.0.0.1:8081;','server 127.0.0.1:8082;')
    config=config.rsplit('}',1)[0]+'server { listen 127.0.0.1:8082; location / { return 200 "$http_x_forwarded_for"; } }}'
    with context.gateway(config) as (name,port):
        def request(path,forward='',body=None):
            c=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
            try:
                c.request('POST',path,body=body,headers={'Host':'mdm.example.test','Origin':'https://mdm.example.test','X-Identity-Request':'1','X-Forwarded-For':forward})
                r=c.getresponse();body=r.read()
                if r.status>=400 and any(r.getheader(k)!=v for k,v in [('Cache-Control','no-store'),('Referrer-Policy','no-referrer'),('X-Content-Type-Options','nosniff')]):raise RuntimeError('gateway rejection omitted security headers')
                return r.status,body
            finally:c.close()
        end=time.monotonic()+30
        while True:
            try:
                if request('/api/probe')[0]==200:break
            except OSError:pass
            if time.monotonic()>end:raise RuntimeError('gateway startup failed')
            time.sleep(.1)
        status, forwarded=request('/api/probe','203.0.113.254')
        if status!=200 or not forwarded or forwarded==b'203.0.113.254':raise RuntimeError('gateway failed to overwrite source header')
        statuses=[]
        for n in range(25):
            status,body=request('/api/v2/tenants/11111111-1111-4111-8111-111111111111/login','203.0.113.'+str(n));statuses.append(status)
            if status==429 and json.loads(body)!={'code':'request_limited'}:raise RuntimeError('incorrect rate-limit response')
        if 200 not in statuses or 429 not in statuses or statuses.count(200)>14:raise RuntimeError('caller-controlled source bypassed login admission')
        time.sleep(3.2)
        if request('/api/v2/tenants/11111111-1111-4111-8111-111111111111/login')[0]!=200:raise RuntimeError('login budget did not recover')
        if request('/api/probe',body='x'*16385)[0]!=413:raise RuntimeError('oversized request was not rejected')
        if request('/api/probe?credential=synthetic-sensitive-value')[0]!=200:raise RuntimeError('gateway probe failed')
        held=[]
        try:
            deadline=time.monotonic()+3
            while len(held)<8:
                connection=socket.create_connection(('127.0.0.1',port),timeout=3)
                connection.sendall(b'POST /api/probe HTTP/1.1\r\nHost: mdm.example.test\r\nContent-Length: 1024\r\nExpect: 100-continue\r\n\r\n')
                reply=b''
                while b'\r\n\r\n' not in reply:
                    chunk=connection.recv(4096)
                    if not chunk:break
                    reply+=chunk
                if reply.startswith(b'HTTP/1.1 100 '):held.append(connection)
                else:
                    connection.close()
                    if time.monotonic()>deadline:raise RuntimeError('could not establish admitted connection set')
                    time.sleep(.05)
            deadline=time.monotonic()+3
            while request('/api/probe','198.51.100.99')[0]!=429:
                if time.monotonic()>deadline:raise RuntimeError('peer connection cap not enforced')
                time.sleep(.05)
        finally:
            for connection in held:connection.close()
        deadline=time.monotonic()+3
        while request('/api/probe')[0]!=200:
            if time.monotonic()>deadline:raise RuntimeError('connection slots did not recover')
            time.sleep(.05)
        statuses = [request('/api/protected', '203.0.113.'+str(n))[0] for n in range(40)]
        if 200 not in statuses or 429 not in statuses: raise RuntimeError('general API admission is not bounded')
        log=subprocess.run(['docker','logs',name],check=True,capture_output=True,text=True,timeout=10)
        if 'synthetic-sensitive-value' in log.stdout+log.stderr or 'mdm_gateway' not in log.stdout:raise RuntimeError('gateway logging contract failed')
        print('login gateway T2: actual peer budget, spoofed forwarding rejection, bounded recovery passed')

def main(context):
    verify(context)
