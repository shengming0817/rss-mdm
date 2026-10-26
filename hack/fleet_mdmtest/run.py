#!/usr/bin/env python3
"""Drive real HTTPS enrollment and policy delivery using the adapted Fleet mdmtest binary."""
import argparse,base64,hashlib,http.cookiejar,json,os,pathlib,plistlib,secrets,select,subprocess,time,urllib.request,uuid

def uid():return str(uuid.uuid4())
def require(ok,message):
    if not ok:raise RuntimeError(message)
class API:
    def __init__(self,args):
        self.origin=args.origin.rstrip('/');self.csrf=None
        self.http=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        x=self.call('POST',f'/api/v1/identity/tenants/{args.tenant}/login',dict(login=args.login,password=args.password_file.read_text().strip()))
        self.csrf=x['csrfToken']
    def call(self,method,path,value=None,*,raw=None):
        time.sleep(.13)
        headers={'Origin':self.origin,'X-Identity-Request':'1'}
        if self.csrf:headers['X-CSRF-Token']=self.csrf
        if value is not None:headers['Content-Type']='application/json';raw=json.dumps(value).encode()
        elif raw is not None:headers['Content-Type']='application/octet-stream'
        if method!='GET':headers['Idempotency-Key']=uid()
        req=urllib.request.Request(self.origin+path,data=raw,method=method,headers=headers)
        try:
            with self.http.open(req,timeout=40) as r:
                b=r.read(8*1024*1024+1);require(len(b)<=8*1024*1024,'HTTP response budget')
                return json.loads(b) if r.headers.get_content_type()=='application/json' else b
        except urllib.error.HTTPError as e:
            e.close();raise RuntimeError(f'{method} {path.split("?")[0]}: HTTP {e.code}') from None
    def change(self,path,revision,input):return self.call('POST',path,dict(operationId=uid(),expectedRevision=revision,input=input))
class Device:
    def __init__(self,binary,config,out):
        self.config=out/'private-config.json';self.config.write_text(json.dumps(config));self.config.chmod(0o600)
        self.error=(out/'client.stderr').open('w');self.p=subprocess.Popen([str(binary),str(self.config)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.error,text=True,bufsize=1)
    def call(self,action,**kwargs):
        self.p.stdin.write(json.dumps(dict(Action=action,**kwargs))+'\n');self.p.stdin.flush()
        require(select.select([self.p.stdout],[],[],90)[0],'Fleet client deadline')
        line=self.p.stdout.readline();require(bool(line),'Fleet client exited; inspect private stderr')
        x=json.loads(line);require(x['ok'],x.get('error','Fleet request failed'));return x.get('result')
    def close(self):
        self.p.stdin.close()
        try:self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:self.p.kill();self.p.wait()
        self.error.close();self.config.unlink(missing_ok=True)
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def main(args):
    os.umask(0o077)
    require(not args.output.exists() or not any(args.output.iterdir()),'output directory must be empty')
    args.output.mkdir(parents=True,exist_ok=True)
    api=API(args);channels=api.call('GET','/api/v1/registration-channels');save(args.output/'channels.json',channels)
    summary={'clientBinarySha256':hashlib.sha256(args.binary.read_bytes()).hexdigest(),'adapterInputs':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in pathlib.Path(__file__).parent.iterdir() if p.is_file()},'fleetRevision':'0aabd28dccba2dae076704507c6c288337300d89','origin':api.origin,'devices':{},'limits':['simulated devices; no real OS settings or APNs wake-up evidence']}
    anonymous=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    checks={}
    for method,path,content,body in [('PUT','/mdm','application/xml',plistlib.dumps(dict(Status='Idle',UDID='anonymous-test'))),('POST','/ManagementServer/MDM.svc','application/vnd.syncml.dm+xml',b'<SyncML xmlns="SYNCML:SYNCML1.2"/>')]:
        request=urllib.request.Request(api.origin+path,data=body,method=method,headers={'Content-Type':content})
        try:
            with anonymous.open(request,timeout=30) as response:code=response.status
        except urllib.error.HTTPError as error:code=error.code
        require(code==401,'anonymous native certificate boundary changed: '+path+': '+str(code));checks[path]=code
    summary['anonymousNativeDenials']=checks
    for platform,source in [('macos','mdm.apple'),('windows','mdm.windows')]:
        if args.platform not in ('both',platform):continue
        out=args.output/platform;out.mkdir(exist_ok=True)
        device='fleet-mdmtest-'+platform+'-'+uid();password=secrets.token_urlsafe(32)
        body=dict(deviceId=device,password=password,source=source)
        if platform=='windows':body['windowsProfile']='Device'
        receipt=api.call('POST','/api/v1/enrollments',body);enrollment=receipt['enrollmentId']
        save(out/'enrollment-request.json',dict(receipt,deviceId=device))
        initial=api.call('GET','/api/v1/enrollments/'+enrollment);save(out/'enrollment-initial.json',initial)
        if platform=='macos':
            profile=api.call('POST',initial['instructions']['profileUrl'],dict(password=password));path=out/'enrollment.mobileconfig';path.write_bytes(profile)
            config=dict(Platform=platform,Profile=str(path))
        else:
            config=dict(Platform=platform,DiscoveryURL=initial['instructions']['discoveryUrl'],Username=initial['instructions']['username'],Password=password,DeviceID=device)
        peer=Device(args.binary,config,out)
        try:
            identity=peer.call('enroll');save(out/'simulated-identity.json',identity)
            first=peer.call('poll');save(out/'first-poll.json',first)
            bound=api.call('GET','/api/v1/enrollments/'+enrollment);save(out/'enrollment-bound.json',bound)
            require(bound['status']=='bound' and bound['progress']['certificateIssued'] and bound['progress']['firstAuthenticatedCheckIn'],'native enrollment did not bind')
            print(platform+' registered '+device,flush=True)
            if not args.enrollment_only:policy_journey(api,peer,platform,device,out,first)
            summary['devices'][platform]=dict(deviceId=device,enrollmentId=enrollment,identity=identity,progress=bound['progress'],policy='not-run' if args.enrollment_only else ('apply-and-removal-verified' if platform=='macos' else 'apply-verified-delete-accepted-effect-unverifiable'))
            save(args.output/'progress.json',summary)
        except Exception as error:
            summary['devices'][platform]=dict(deviceId=device,enrollmentId=enrollment,status='failed',error=str(error))
            save(args.output/'progress.json',summary)
            print(platform+' failed: '+str(error),flush=True)
        finally:
            peer.close()
            # Keep only simulator-owned resources in the cleanup scope.
            policy_file=out/'policy.json'
            if policy_file.exists():
                pid=json.loads(policy_file.read_text())['policyId'];current=api.call('GET','/api/v1/policies/'+pid)
                if current['state']=='enabled':api.change('/api/v1/policies/'+pid,current['revision'],dict(action='put',enabled=False,definition=current['definition']))
            current=api.call('GET','/api/v1/enrollments/'+enrollment)
            if current['registrationId']:api.call('POST','/api/v1/devices/'+device+'/registrations/'+current['registrationId']+'/revoke',{})
            elif current['status']=='pending':api.call('POST','/api/v1/enrollments/'+enrollment+'/cancel',{})
            save(out/'cleanup.json',dict(deviceId=device,credentialsRevoked=bool(current['registrationId'])))
    summary['status']='failed' if any(v.get('status')=='failed' for v in summary['devices'].values()) else 'passed'
    save(args.output/'result.json',summary)
    print(json.dumps(summary,indent=2))
    if any(v.get('status')=='failed' for v in summary['devices'].values()):raise SystemExit(1)
def policy_journey(api,peer,platform,device,out,first):
    scope,resource,policy=uid(),uid(),uid();architecture='aarch64' if platform=='macos' else 'x86_64'
    identifier='com.rss.fleet-mdmtest.'+uid();marker='Fleet mdmtest '+uid()
    if platform=='macos':
        profile=dict(identifier=identifier,uuid=uid(),metadata={},payloads=[dict(schema='mdm/profiles/com.apple.loginwindow.yaml',identifier=identifier+'.text',uuid=uid(),metadata={},fields=dict(LoginwindowText=dict(type='string',value=marker)))])
        apply=dict(platform=platform,request=dict(kind='install_profile',profile=profile));remove=dict(platform=platform,request=dict(kind='remove_profile',identifier=identifier,uuid=profile['uuid']))
    else:
        node='./Device/Vendor/MSFT/Policy/Config/Experience/AllowCortana'
        def task(remove):return dict(platform=platform,request=dict(kind='sync_ml',request=dict(kind='node',node=node,instance=[],operation='delete' if remove else 'replace',value=None if remove else dict(type='integer',value='1'))))
        apply,remove=task(False),task(True)
    content=json.dumps(dict(target=dict(kind='device'),apply=apply,remove=remove),separators=(',',':')).encode()
    path='/api/v1/resources/'+resource
    api.change(path,0,dict(action='create',kind='configuration'))
    api.change(path,1,dict(action='version',version='v1',kind='configuration',variants=[dict(platform=platform,architecture=architecture,key='default',declaration=dict(kind='configuration',artifact=dict(reference='native-input',length=len(content),sha256=list(hashlib.sha256(content).digest()))))]))
    api.call('POST',path+f'/content?version=v1&variant=default&platform={platform}&architecture={architecture}&operation='+uid(),raw=content)
    api.change(path,2,dict(action='activate',version='v1'))
    api.change('/api/v1/scopes/'+scope,0,dict(action='put',definition=dict(targets=[dict(kind='device',id=device)],limitations=None,exclusions=[])))
    definition=dict(scope=scope,action=dict(kind='configuration',resource=dict(id=resource,version='v1',platform=platform,architecture=architecture,variant='default'),exit='remove'))
    api.change('/api/v1/policies/'+policy,0,dict(action='put',enabled=True,definition=definition))
    save(out/'policy.json',dict(scopeId=scope,resourceId=resource,policyId=policy,marker=marker,identifier=identifier))
    def process(reply,phase):
        if platform=='macos':
            if not reply:return None,False
            raw=plistlib.loads(base64.b64decode(reply['Raw']));command=raw['Command'];kind=command['RequestType']
            save(out/(phase+'-command-'+reply['CommandUUID']+'.json'),dict(commandUUID=reply['CommandUUID'],requestType=kind,payloadSha256=hashlib.sha256(base64.b64decode(reply['Raw'])).hexdigest()))
            matched=kind==('InstallProfile' if phase=='apply' else 'RemoveProfile')
            if matched:
                if phase=='apply':
                    payload=command['Payload']
                    # Profiles are signed by the actual product signer; decode CMS without editing bytes.
                    r=subprocess.run(['openssl','cms','-verify','-inform','DER','-noverify'],input=payload,capture_output=True,check=True)
                    profile=plistlib.loads(r.stdout)
                    matched=profile['PayloadIdentifier']==identifier
                    if matched:require(marker in str(profile),'wrong configuration profile delivered')
                else:matched=command['Identifier']==identifier
            require(kind in ['InstallProfile','RemoveProfile','DeviceInformation','DeviceConfigured','SecurityInfo','ProfileList','InstalledApplicationList','CertificateList','UserList'],'unexpected Apple command '+kind)
            return peer.call('ack',CommandUUID=reply['CommandUUID']),matched
        matched=False
        for op in (reply or {}).values():
            text=json.dumps(op)
            if node in text and op['Verb']==('Replace' if phase=='apply' else 'Delete'):
                if phase=='apply':require(any(item.get('Target')==node and item.get('Data',{}).get('Content')=='1' for item in op['Cmd']['Items']),'wrong CSP value')
                matched=True
        if any(op['Verb']!='Status' for op in (reply or {}).values()):return peer.call('ack'),matched
        return None,False
    reply=first
    for phase in ['apply','remove']:
        end=time.monotonic()+120;observed=False
        while time.monotonic()<end and not observed:
            if reply is None:reply=peer.call('poll')
            save(out/(phase+'-last-poll.json'),reply)
            reply,observed=process(reply,phase)
            if not observed:time.sleep(.5)
        require(observed,platform+' '+phase+' native delivery deadline')
        print(platform+' '+phase+' received and acknowledged',flush=True)
        # Consume subsequent ProfileList/Get evidence and require durable server acceptance.
        verified=False;verify_end=time.monotonic()+60
        while time.monotonic()<verify_end:
            if reply is not None:reply,_=process(reply,phase)
            operation_page=api.call('GET','/api/v1/policies/'+policy+'/assignments');save(out/(phase+'-assignments.json'),operation_page)
            records=api.call('GET','/api/v1/operations?filter=device=='+device+'&limit=100');save(out/(phase+'-operations.json'),records)
            ids={i for item in operation_page['items'] for i in item['operationIds']} if phase=='apply' else {r['id'] for r in records['items'] if r['id'] not in baseline and r['kind']=='command'}
            details=[api.call('GET','/api/v1/devices/'+device+'/operations/'+i) for i in ids]
            save(out/(phase+'-details.json'),details)
            if details and all(r['commandStatus']=='applied' or (platform=='windows' and phase=='remove' and r['observation'].get('effect')=='unverifiable' and r['observation'].get('effectReason')=='delete_restores_default_without_frozen_detector' and any(v.get('kind')=='delete' and v.get('accepted') and v.get('status')==200 for v in r['observation']['receipts'])) for r in details):verified=True;break
            if reply is None:time.sleep(.4);reply=peer.call('poll')
        require(verified,platform+' '+phase+' server evidence deadline')
        model=peer.call('state');save(out/(phase+'-simulated-state.json'),model)
        if platform=='macos':require((identifier in model)==(phase=='apply'),'simulated profile state mismatch')
        else:require((model.get(node)=='1') if phase=='apply' else node not in model,'simulated CSP state mismatch')
        if phase=='apply':
            baseline={r['id'] for r in records['items']}
            old=api.call('GET','/api/v1/policies/'+policy)
            api.change('/api/v1/policies/'+policy,old['revision'],dict(action='put',enabled=False,definition=definition))
    save(out/'final-policy.json',api.call('GET','/api/v1/policies/'+policy))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--origin',required=True);p.add_argument('--tenant',required=True);p.add_argument('--login',default='administrator');p.add_argument('--password-file',type=pathlib.Path,required=True);p.add_argument('--binary',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--platform',choices=['both','macos','windows'],default='both');p.add_argument('--enrollment-only',action='store_true');main(p.parse_args())
