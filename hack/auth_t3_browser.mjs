// Product-only acceptance. ref: microsoft/playwright v1.60.0 browserContext.ts
import fs from 'node:fs';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
import {execFileSync} from 'node:child_process';
const require=createRequire(import.meta.url);
const {chromium}=require('/opt/playwright-core');
const input=JSON.parse(fs.readFileSync('/fixture/browser-input.json','utf8'));
const origin='https://mdm.example.test', other='https://mdm-other.example.test';
const api=`/api/v2/tenants/${input.tenant}`;
const inventory='/api/v1/devices/device-1/inventory?source=mdm.windows';
const checks={}, requests=[], privateValues=[];
let stage='launch';
const assert=(ok,message)=>{if(!ok)throw new Error(message)};
const docker=(args,stdin)=>execFileSync('docker',args,{input:stdin,encoding:'utf8',stdio:['pipe','pipe','pipe'],timeout:65000}).trim();
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function poll(check,seconds=60){const end=Date.now()+seconds*1000;while(Date.now()<end){try{if(await check())return}catch{}await delay(500)}throw new Error('readiness deadline')}
const browser=await chromium.launch({headless:true,args:['--no-sandbox']});
const consoleText=[];
async function pageAt(url=origin){const ctx=await browser.newContext({locale:'en-US'});const page=await ctx.newPage();page.setDefaultTimeout(15000);page.on('console',m=>consoleText.push(m.text()));await page.goto(`${url}/tenants/${url===origin?input.tenant:input.otherTenant}/login`);return page}
async function request(page,path,method='GET',body,headers={}){
  const result=await page.evaluate(async ({path,method,body,headers})=>{
    const r=await fetch(path,{method,credentials:'same-origin',headers:{'Content-Type':'application/json','X-Identity-Request':'1',...headers},...(body===undefined?{}:{body:JSON.stringify(body)})});
    const text=await r.text();let value=null;try{value=JSON.parse(text)}catch{}
    return {status:r.status,value,id:r.headers.get('x-request-id')};
  },{path,method,body,headers});
  requests.push({stage,method,path:path.split('?')[0],status:result.status,requestId:result.id});
  return result;
}
async function post(page,path,body,token){
  if(token===undefined){const session=await request(page,api+'/session');assert(session.status===200,'session before write');token=session.value.csrfToken}
  return request(page,path,'POST',body,{'X-CSRF-Token':token});
}
async function login(page,user,password){
  await delay(3100); // Respect the real ingress rate policy; do not widen it for tests.
  await page.goto(origin+`/tenants/${input.tenant}/login`);
  await page.locator('#login-name').fill(user);await page.locator('#login-password').fill(password);
  await page.locator('form button[type=submit]').click();
  await page.waitForURL('**/sessions');
  const r=await request(page,api+'/session');assert(r.status===200,'UI login');return r.value;
}
async function logoutUI(page,all=false){
  await page.goto(origin+`/tenants/${input.tenant}/sessions`);
  const route=all?api+'/sessions/logout-all':api+'/session/logout';
  const response=page.waitForResponse(r=>new URL(r.url()).pathname===route&&r.request().method()==='POST');
  await page.getByRole('button',{name:all?/all.*session|全部|所有/i:/^Sign out$|^Log out$|^退出$/i}).click();
  assert((await response).status()===204,'UI logout');
}
async function cloneSession(page,url=origin){const ctx=await browser.newContext({locale:'en-US'});const cookies=await page.context().cookies(origin);await ctx.addCookies(cookies.map(c=>({...c,domain:new URL(url).hostname})));const p=await ctx.newPage();await p.goto(url+'/');return p}
async function restart(){docker(['restart','--time','45',input.server]);await poll(async()=> (await request(admin,'/readyz')).status===200)}
function sql(statement){return docker(['exec','-i',input.pg,'psql','-X','-At','-v','ON_ERROR_STOP=1','-U','postgres','-d','mdm_test'],statement)}
async function keycloak(page,user){
  await page.waitForURL('https://idp.example.test:8443/**');
  await page.locator('#username').fill(user);await page.locator('#password').fill(input.idpPassword);
  await page.locator('#kc-login').click();
}
let admin,member;
try{
  stage='local_ui';admin=await pageAt();await login(admin,'admin',input.adminPassword);
  member=await pageAt();const initial=await login(member,'member',input.memberPassword);
  assert(initial.identity.principalId===input.member,'member coordinate');
  const context=await request(member,`/api/identity-host/v1/tenants/${input.tenant}/context`);
  assert(context.status===200&&context.value.sessionId===initial.session.id&&!context.value.navigation.manageAccounts,'host context');checks.local_ui=true;

  stage='account_ui';await admin.goto(origin+`/tenants/${input.tenant}/accounts`);
  await admin.locator('#account-login').fill('ui-created');await admin.locator('#account-password').fill(input.memberPassword);
  const created=admin.waitForResponse(r=>new URL(r.url()).pathname===api+'/accounts'&&r.request().method()==='POST');
  await admin.locator('form').filter({has:admin.locator('#account-login')}).locator('button').click();
  assert((await created).status()===201,'UI account creation');await admin.getByRole('cell',{name:/ui-created/}).waitFor();checks.account_ui=true;

  stage='inventory';let r=await request(member,inventory);
  assert(r.status===200&&r.value.fields.some(f=>f.last_good?.value==='Model-2364'),'real authorized inventory');
  assert((await request(member,'/api/v1/devices/outside/inventory?source=mdm.windows')).status===403,'device scope');checks.inventory=true;

  stage='permissions';const group=crypto.randomUUID(),groupPath='/api/v1/groups/'+group;
  const change={operationId:crypto.randomUUID(),expectedRevision:0,input:{action:'create',name:'T3-2364',description:'product authorization fixture',criteria:null}};
  assert((await post(member,groupPath,change)).status===403,'management deny');
  assert(sql(`SELECT count(*) FROM mdm_group.groups WHERE id='${group}'`)==='0','denied write had effect');
  assert((await post(admin,groupPath,change)).status===200,'management permit');
  assert((await request(admin,groupPath)).status===200,'management read');
  const publisher='/api/v1/software-sources/unconfigured/candidates/candidate-2364';
  assert((await request(member,publisher)).status===403,'publisher permission deny');
  assert((await request(admin,publisher)).status===404,'publisher permitted source lookup');
  assert((await request(member,api+'/accounts')).status===403,'hidden accounts not authoritative');checks.permissions=true;

  stage='cookie_csrf';const cookie=(await member.context().cookies(origin)).find(c=>c.name==='__Host-identity-session');
  assert(cookie&&cookie.secure&&cookie.httpOnly&&cookie.sameSite==='Lax'&&cookie.path==='/'&&cookie.domain==='mdm.example.test','cookie attributes');
  assert(!await member.evaluate(()=>document.cookie.includes('__Host-identity-session')),'HttpOnly');
  assert((await request(member,api+'/session/refresh','POST',undefined)).status===403,'missing csrf');
  assert((await request(member,api+'/session/refresh','POST',undefined,{'X-CSRF-Token':'wrong'})).status===403,'incorrect csrf');
  const attacker=await pageAt(other);
  const cross=await attacker.evaluate(async origin=>{try{await fetch(origin+'/api/v2/tenants/11111111-1111-4111-8111-111111111111/session/logout',{method:'POST',credentials:'include'});return false}catch{return true}},origin);
  assert(cross&&(await request(member,api+'/session')).status===200,'cross origin logout');checks.cookie_csrf=true;

  stage='refresh';const stale=await cloneSession(member);
  assert((await post(member,api+'/session/refresh')).status===200,'refresh');
  assert((await request(stale,'/api/v1/authorization')).status===401,'rotated credential');await stale.context().close();checks.refresh=true;

  stage='restart';const before=(await request(member,api+'/session')).value.session.id;await restart();
  assert((await request(member,api+'/session')).value.session.id===before,'session restart persistence');checks.restart=true;

  stage='isolation';assert((await request(attacker,'/api/v1/authorization')).status===401,'host cookie isolation');
  const replay=await cloneSession(member,other);assert((await request(replay,'/api/v1/authorization')).status===401,'instance replay');
  assert((await request(member,`/api/v2/tenants/${input.otherTenant}/session`)).status===401,'tenant replay');
  assert((await request(member,`/api/identity-host/v1/tenants/${input.otherTenant}/context`)).status===401,'context tenant replay');
  await replay.context().close();await attacker.context().close();checks.isolation=true;

  for(const [field,key] of [['enabled','account_disabled'],['membership','membership_removed']]){
    stage=key;const old=await cloneSession(member);
    assert((await post(admin,`${api}/accounts/${input.member}/${field}`,{enabled:false})).status===200,'disable account/membership');
    assert((await request(member,inventory)).status===401,'disabled new request');
    assert((await post(admin,`${api}/accounts/${input.member}/${field}`,{enabled:true})).status===200,'restore account/membership');
    await restart();assert((await request(old,inventory)).status===401,'revocation resurrected');
    await old.context().close();await member.context().clearCookies();await login(member,'member',input.memberPassword);checks[key]=true;
  }
  stage='logout';const old=await cloneSession(member);await logoutUI(member);
  assert((await request(old,inventory)).status===401,'logout authority');await old.context().close();checks.logout=true;
  await login(member,'member',input.memberPassword);
  stage='logout_all';const second=await pageAt();await login(second,'member',input.memberPassword);
  await logoutUI(member,true);assert((await request(second,inventory)).status===401,'all sessions revoked');await second.context().close();checks.logout_all=true;
  await login(member,'member',input.memberPassword);

  stage='enterprise';const probe=await browser.newPage();await poll(async()=>{const r=await probe.goto(input.issuer+'/.well-known/openid-configuration');return r.status()===200});await probe.close();
  const settings={issuer:input.issuer,clientId:'mdm',redirectUri:origin+'/api/v2/oidc/callback',scopes:['openid','profile','email'],claims:{email:'email',groups:null},jit:false};
  r=await post(admin,api+'/providers',{settings,clientSecret:input.clientSecret,caPem:fs.readFileSync('/fixture/ca.crt','utf8')});
  assert(r.status===201,'provider create');const provider=r.value.id;
  assert((await post(admin,`${api}/providers/${provider}/enabled`,{expectedVersion:r.value.version,enabled:true})).status===200,'provider enable');
  await member.goto(origin+`/tenants/${input.tenant}/sessions`);
  await member.locator('#link-provider').selectOption(provider);await member.locator('#link-password').fill(input.memberPassword);
  await member.locator('form').filter({has:member.locator('#link-provider')}).locator('button').click();
  await keycloak(member,'alice');await member.waitForURL('**/sessions');
  assert((await request(member,api+'/session')).value.identity.principalId===input.member,'link changed subject');
  await logoutUI(member);await member.context().clearCookies();
  await member.goto(origin+`/tenants/${input.tenant}/login`);
  await member.getByRole('button',{name:/SSO|企业|单点/i}).click();await keycloak(member,'alice');await member.waitForURL('**/sessions');
  assert((await request(member,api+'/session')).value.identity.principalId===input.member,'SSO subject binding');
  assert((await request(member,inventory)).status===200,'SSO authorized resource');
  assert((await request(member,api+'/accounts')).status===403,'SSO unauthorized resource');checks.enterprise=true;

  stage='unknown_subject';const unknown=await pageAt();await unknown.getByRole('button',{name:/SSO|企业|单点/i}).click();await keycloak(unknown,'unknown');
  await unknown.waitForURL(origin+'/**');assert((await request(unknown,api+'/session')).status===401,'unknown subject');await unknown.context().close();checks.unknown_subject=true;

  stage='private_binding';const deniedSettings={...settings,clientId:'unapproved-client'};
  r=await post(admin,api+'/providers',{settings:deniedSettings,clientSecret:input.clientSecret,caPem:fs.readFileSync('/fixture/ca.crt','utf8')});
  assert(r.status===201,'unapproved provider persisted without network access');
  const tested=await post(admin,`${api}/providers/${r.value.id}/test`,{expectedVersion:r.value.version});
  assert(tested.status!==200,'unapproved private client connected');checks.private_binding=true;

  stage='idp_down';docker(['stop','--time','10',input.idp]);const independent=await pageAt();await login(independent,'admin',input.adminPassword);
  assert((await request(independent,api+'/accounts')).status===200,'IdP-independent account management');
  assert((await request(independent,inventory)).status===200,'IdP-independent request');
  const createdLocal=await post(independent,api+'/accounts',{login:'while-idp-down',password:input.memberPassword});assert(createdLocal.status===201,'IdP-independent account write');checks.idp_down=true;

  stage='pg_down';const persisted=await cloneSession(independent);const outageCsrf=(await request(independent,api+'/session')).value.csrfToken;docker(['pause',input.pg]);
  try{
    assert((await request(independent,inventory)).status===503,'PG unavailable authorizes');
    assert((await request(independent,api+'/session/logout','POST',undefined,{'X-CSRF-Token':outageCsrf})).status===503,'PG down reports logout success');
  }finally{docker(['unpause',input.pg])}
  await restart();assert((await request(persisted,api+'/session')).status===200,'failed logout lost authoritative session');
  assert((await post(persisted,api+'/session/logout')).status===204,'recovery logout');checks.pg_down=true;

  stage='safe_logs';for(const value of [input.adminPassword,input.memberPassword,input.idpPassword,input.clientSecret])assert(!consoleText.join('\n').includes(value),'console secret');
  assert(!consoleText.some(v=>/[?&]code=/.test(v)),'console callback code');
  for(const page of [admin,member,independent,persisted]){
    assert(!/[?&](code|state)=/.test(page.url()),'callback remains in application URL');
    const cookies=await page.context().cookies();for(const c of cookies)privateValues.push(c.value);
  }
  checks.safe_logs=true;
  const result={checks,requests,browser:browser.version(),privateValues};
  await browser.close();process.stdout.write(JSON.stringify(result));
}catch(error){await browser.close();process.stderr.write(JSON.stringify({stage,errorClass:error.name,reason:error.message.replace(/https?:\/\/\S+/g,'[url]')}));process.exitCode=1}
