"""One run-owned TLS RustFS fixture, reusable by content.s3 and its product consumer.

ref: rustfs/rustfs rustfs/src/admin/handlers/user.rs@1.0.0.
Image identity belongs to fixtures/s3-provider.lock.json. No production deployment wiring.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import threading
import time
from t2_environment import Environment, ROOT, private, run
from t2_processes import private_value

PROVIDER = json.loads((ROOT / 'fixtures/s3-provider.lock.json').read_text())

class S3Environment:
    def __init__(self, *, group='t2-s3', bucket='content'):
        self.owner = Environment(group=group)
        self.bucket = bucket
        self.name = self.owner.project
        self.lock = threading.RLock()
        self.ready = False

    def reset(self):
        with self.lock:
            ids = run(['docker','ps','-aq','--filter',f'name=^/{self.name}$'],capture_output=True,timeout=30).stdout.split()
            for identifier in ids:
                info = json.loads(run(['docker','inspect',identifier],capture_output=True,timeout=30).stdout)[0]
                labels = info.get('Config',{}).get('Labels') or {}
                if info.get('Name') != '/' + self.name or labels.get('rss.mdm.worktree') != self.owner.identity or labels.get('rss.mdm.fixture') != 'content-s3':
                    raise RuntimeError('S3 fixture ownership mismatch')
                run(['docker','rm','-f','-v',identifier],capture_output=True,timeout=30)
            self.ready = False

    def execute(self, *args):
        return run(['docker','exec',self.name,*args],capture_output=True,timeout=15).stdout

    def signed(self, method, path, body='/dev/null', *, content_type=None):
        args = ['curl','--fail','--silent','--show-error','--max-time','10','--cacert','/tls/ca.pem',
                '--aws-sigv4','aws:amz:us-east-1:s3','--user',self.auth,'--request',method]
        if content_type:
            args += ['--header','Content-Type: '+content_type]
        args += ['--data-binary','@'+body,'https://localhost:9000/'+path]
        return self.execute(*args)

    def prepare(self):
        with self.lock:
            if self.ready:
                return self.configuration
            self.reset()
            self.owner.certificate()
            root = self.owner.root
            root.chmod(0o700)
            tls = root / 'tls'
            tls.mkdir(exist_ok=True,mode=0o755)
            for source,target in [('ca.crt','ca.pem'),('server.crt','rustfs_cert.pem'),('server.key','rustfs_key.pem')]:
                shutil.copyfile(root/source,tls/target)
                # Only the disposable container's copy needs non-root-readable TLS files.
                (tls/target).chmod(0o644)
            root_access='fixture-root'
            root_secret=os.urandom(32).hex()
            access='fixture-content'
            secret=os.urandom(32).hex()
            self.auth=root_access+':'+root_secret
            private_value(root_secret);private_value(secret);private_value(self.auth)
            envfile=private(root/'provider.env',f'RUSTFS_ACCESS_KEY={root_access}\nRUSTFS_SECRET_KEY={root_secret}\nRUSTFS_TLS_PATH=/tls\nRUSTFS_CONSOLE_ENABLE=false\n')
            run(['docker','create','--name',self.name,'--label','rss.mdm.worktree='+self.owner.identity,
                 '--label','rss.mdm.fixture=content-s3','--env-file',envfile,'-p','127.0.0.1::9000',PROVIDER['image']],capture_output=True,timeout=120)
            try:
                try:
                    run(['docker','cp',tls,self.name+':/tls'],capture_output=True,timeout=30)
                finally:
                    (tls/'rustfs_key.pem').chmod(0o600)
                run(['docker','start',self.name],capture_output=True,timeout=30)
                port=run(['docker','port',self.name,'9000/tcp'],capture_output=True,timeout=30).stdout.strip().rsplit(':',1)[1]
                self.configuration=dict(endpoint='https://localhost:'+port,region='us-east-1',bucket=self.bucket,namespace='content',
                                        ca=str(root/'ca.crt'),certificate=str(root/'server.crt'),key=str(root/'server.key'),accessKey=access,secretKey=secret,rootAccessKey=root_access,rootSecretKey=root_secret,
                                        provider=PROVIDER['provider'],version=PROVIDER['version'],image=PROVIDER['image'])
                deadline=time.monotonic()+45
                while True:
                    try:
                        self.signed('GET','')
                        break
                    except Exception:
                        if time.monotonic() >= deadline:
                            raise RuntimeError('S3 fixture TLS readiness deadline exceeded') from None
                        time.sleep(.1)
                for bucket in (self.bucket,'neighbor','unversioned'):
                    self.signed('PUT',bucket)
                private(root/'versioning.xml','<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>')
                run(['docker','cp',root/'versioning.xml',self.name+':/versioning.xml'],capture_output=True,timeout=30)
                run(['docker','exec','--user','0',self.name,'chown','rustfs:rustfs','/versioning.xml'],capture_output=True,timeout=30)
                self.signed('PUT',self.bucket+'?versioning','/versioning.xml',content_type='application/xml')
                policy=dict(Version='2012-10-17',Statement=[
                    dict(Effect='Allow',Action=['s3:GetBucketVersioning'],Resource=['arn:aws:s3:::'+self.bucket,'arn:aws:s3:::unversioned']),
                    dict(Effect='Allow',Action=['s3:ListBucketMultipartUploads'],Resource=['arn:aws:s3:::'+self.bucket],Condition={'StringLike':{'s3:prefix':['content/*']}}),
                    dict(Effect='Allow',Action=['s3:PutObject','s3:GetObject','s3:GetObjectVersion','s3:DeleteObjectVersion','s3:AbortMultipartUpload','s3:ListMultipartUploadParts'],Resource=['arn:aws:s3:::'+self.bucket+'/content/*'])])
                private(root/'policy.json',policy)
                private(root/'user.json',dict(secretKey=secret,status='enabled'))
                for name in ('policy.json','user.json'):
                    run(['docker','cp',root/name,self.name+':/'+name],capture_output=True,timeout=30)
                run(['docker','exec','--user','0',self.name,'chown','rustfs:rustfs','/policy.json','/user.json'],capture_output=True,timeout=30)
                for path,body in [('add-canned-policy?name=content-workload','/policy.json'),
                                  ('add-user?accessKey='+access,'/user.json'),
                                  ('set-user-or-group-policy?policyName=content-workload&userOrGroup='+access+'&isGroup=false','/dev/null')]:
                    self.signed('PUT','rustfs/admin/v3/'+path,body,content_type='application/json')
                private(root/'connection.json',self.configuration)
                self.ready=True
                return self.configuration
            except BaseException:
                self.reset()
                raise

    def environment(self):
        self.prepare()
        return {'MDM_S3_FIXTURE':str(self.owner.root/'connection.json')}
