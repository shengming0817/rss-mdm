"""Run the actual login rate profile against a scoped local content server, not a mock Identity."""
import http.client
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
import json
import sys
ROOT=Path(__file__).resolve().parents[1]

def verify(image):
    if '@sha256:' not in image:raise RuntimeError('fixed gateway image required')
    name='mdm-login-rate-'+uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix=name+'-') as tmp:
        root=Path(tmp)
        # Only TLS/file/listener locations are adapted for this loopback protocol seam.
        # The source-key, budget, burst, error and location rules are the production file.
        config=(ROOT/'deployment/nginx.conf').read_text()
        config=config.replace('listen 443 ssl;','listen 8080;').replace('ssl_certificate /private/mdm-tls.crt;','').replace('ssl_certificate_key /private/mdm-tls.key;','')
        config=config.replace('server 127.0.0.1:8081;','server 127.0.0.1:8082;')
        config=config.rsplit('}',1)[0]+'server { listen 127.0.0.1:8082; location / { return 200 "{}"; } }}'
        (root/'nginx.conf').write_text(config)
        try:
            subprocess.run(['docker','run','-d','--rm','--name',name,'--label','rss.test=2343','-p','127.0.0.1::8080','-v',str(root/'nginx.conf')+':/tmp/input.conf:ro',image,'nginx','-e','stderr','-c','/tmp/input.conf','-g','daemon off;'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            port=int(subprocess.check_output(['docker','port',name,'8080'],text=True).strip().rsplit(':',1)[1])
            def request(path,forward=''):
                c=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
                try:
                    c.request('POST',path,headers={'Host':'mdm.example.test','Origin':'https://mdm.example.test','X-MDM-Request':'1','X-Forwarded-For':forward})
                    r=c.getresponse();body=r.read();return r.status,body
                finally:c.close()
            end=time.monotonic()+30
            while True:
                try:
                    if request('/probe')[0]==200:break
                except OSError:pass
                if time.monotonic()>end:raise RuntimeError('gateway startup failed')
                time.sleep(.1)
            statuses=[]
            for n in range(25):
                status,body=request('/auth/login','203.0.113.'+str(n));statuses.append(status)
                if status==429 and json.loads(body)!={'code':'login_rate_limited'}:raise RuntimeError('incorrect rate-limit response')
            if 200 not in statuses or 429 not in statuses or statuses.count(200)>14:raise RuntimeError('caller-controlled source bypassed login admission')
            time.sleep(3.2)
            if request('/auth/login')[0]!=200:raise RuntimeError('login budget did not recover')
            print('login gateway T2: actual peer budget, spoofed forwarding rejection, bounded recovery passed')
        finally:
            primary=sys.exception()
            try:
                subprocess.run(['docker','rm','-f',name],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
            except Exception:
                if primary is None:raise RuntimeError('login gateway cleanup failed') from None
                primary.add_note('login gateway cleanup also failed')
