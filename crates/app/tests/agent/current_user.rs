//! Device mTLS and the existing enterprise session jointly bind the current user.
use crate::test_support::{agent::*, agent_execution::Fixture, http::Browser, runtime::*, *};
use anyhow::Context;
const CURRENT: &str = "/api/v1/agent/runtime/current-user";
async fn call(
    f: &Fixture,
    method: Method,
    value: Option<Value>,
    device: bool,
    user: bool,
) -> Result<(StatusCode, Value)> {
    let mut request = Request::builder()
        .method(method)
        .uri(CURRENT)
        .header("host", "mdm.example.test:9445");
    if device {
        request = request
            .extension(evidence(crate::test_support::agent_execution::case_credential()).unwrap());
    }
    if user {
        request = request.header(
            "x-rss-user-session",
            &f.author.cookies["__Host-identity-session"],
        );
    }
    if value.is_some() {
        request = request.header("content-type", "application/json");
    }
    let body = value
        .map(|v| serde_json::to_vec(&v))
        .transpose()?
        .unwrap_or_default();
    let response = f
        .router
        .clone()
        .oneshot(request.body(Body::from(body))?)
        .await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&bytes)?))
}
async fn owner(f: &mut Fixture, change: Option<Value>) -> Result<Value> {
    let path = format!(
        "/api/v1/devices/{}/registration-user",
        crate::test_support::agent_execution::case_device_id()
    );
    let previous = f.author.operation.replace(Uuid::new_v4());
    let out = f
        .author
        .call(
            &f.router,
            if change.is_some() {
                Method::PUT
            } else {
                Method::GET
            },
            &path,
            change,
        )
        .await?;
    f.author.operation = previous;
    ensure!(out.0 == StatusCode::OK, "owner: {out:?}");
    Ok(out.1)
}
#[tokio::test]
#[ignore = "MODULE=agent.current_user: real identity, device authority, atomic owner initialization and CAS"]
async fn login_switch_logout_replay_and_concurrent_first_login() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        f.register_profile(json!(["inventory.collect.v1"])).await?;
        ensure!(owner(&mut f,None).await?["user"].is_null());
        ensure!(call(&f,Method::GET,None,true,false).await?.1["revision"]==0);
        let login=json!({"operationId":Uuid::new_v4(),"expectedRevision":0});
        ensure!(call(&f,Method::PUT,Some(login.clone()),false,true).await?.0==StatusCode::UNAUTHORIZED);
        ensure!(call(&f,Method::PUT,Some(login.clone()),true,false).await?.0==StatusCode::UNAUTHORIZED);
        let mut forged=login.clone();forged["user"]=json!({"principalId":Uuid::new_v4()});
        ensure!(call(&f,Method::PUT,Some(forged),true,true).await?.0==StatusCode::BAD_REQUEST);
        let competing=json!({"operationId":Uuid::new_v4(),"expectedRevision":0});
        let (a,b)=tokio::join!(call(&f,Method::PUT,Some(login.clone()),true,true),call(&f,Method::PUT,Some(competing.clone()),true,true));
        let (a,b)=(a?,b?);
        ensure!([a.0,b.0].contains(&StatusCode::OK)&&[a.0,b.0].contains(&StatusCode::CONFLICT),"CAS: {a:?} {b:?}");
        let accepted=if a.0==StatusCode::OK {login}else{competing};
        let first=call(&f,Method::GET,None,true,false).await?;
        ensure!(first.0==StatusCode::OK && first.1["state"]=="active" && first.1["user"]["principalId"]==f.author_id);
        let initial_owner=owner(&mut f,None).await?;
        ensure!(initial_owner["revision"]==1 && initial_owner["user"]==first.1["user"]);
        let cleared=owner(&mut f,Some(json!({"expectedRevision":initial_owner["revision"],"user":null}))).await?;
        ensure!(call(&f,Method::PUT,Some(accepted.clone()),true,true).await?.1==first.1);
        ensure!(owner(&mut f,None).await?["user"].is_null(),"replay reinitialized a cleared owner");
        let next=json!({"operationId":Uuid::new_v4(),"expectedRevision":first.1["revision"]});
        let bound=call(&f,Method::PUT,Some(next),true,true).await?;
        ensure!(bound.0==StatusCode::OK);
        let filled=owner(&mut f,None).await?;
        ensure!(filled["revision"].as_u64()==Some(cleared["revision"].as_u64().unwrap()+1) && filled["user"]==initial_owner["user"]);
        let old_author=f.author.clone();
        f.author=crate::test_support::authority::Authority::prepared_browser("admin")?;
        let admin=crate::test_support::http::browser_subject(&f.author,&f.router).await?;
        crate::test_support::identity::seed_grants(case_tenant(),&admin,f.grants.clone()).await?;
        let switch=json!({"operationId":Uuid::new_v4(),"expectedRevision":bound.1["revision"]});
        let switched=call(&f,Method::PUT,Some(switch),true,true).await?;
        ensure!(switched.0==StatusCode::OK && switched.1["user"]["principalId"]==admin);
        ensure!(owner(&mut f,None).await?["user"]==initial_owner["user"],"switch transferred ownership");
        let stale=json!({"operationId":Uuid::new_v4(),"expectedRevision":bound.1["revision"]});
        ensure!(call(&f,Method::DELETE,Some(stale),true,false).await?.0==StatusCode::CONFLICT);
        let logout=json!({"operationId":Uuid::new_v4(),"expectedRevision":switched.1["revision"]});
        let logged_out=call(&f,Method::DELETE,Some(logout.clone()),true,false).await?;
        ensure!(logged_out.0==StatusCode::OK && logged_out.1["state"]=="unbound");
        ensure!(call(&f,Method::DELETE,Some(logout),true,false).await?.1==logged_out.1);
        f.author=old_author;
        let rebound=call(&f,Method::PUT,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":logged_out.1["revision"]})),true,true).await?;
        ensure!(rebound.0==StatusCode::OK);
        let (identity,identity_resources)=crate::test_support::identity::identity(case_tenant()).await?;
        identity_resources.finish(async {
            let session=identity.authority.inspect_session(identity.tenant,rss_identity_core::session::SessionSecret::parse(f.author.cookies["__Host-identity-session"].clone())?,crate::identity::deadline()).await?;
            identity.authority.revoke_current_session(session,crate::identity::deadline()).await?;
            let invalid=call(&f,Method::GET,None,true,false).await?;
            ensure!(invalid.0==StatusCode::OK && invalid.1["state"]=="invalidated" && invalid.1["user"].is_null(),"revocation: {invalid:?}");
            Ok(())
        }).await
    }).await
}

#[tokio::test]
#[ignore = "MODULE=agent.current_user: directory people authorization, session revocation and device generation/credential fences"]
async fn directory_people_are_verified_and_authorized_before_search() -> Result<()> {
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let registered=f.register_profile(json!(["inventory.collect.v1"])).await?;
        let device=crate::test_support::agent_execution::case_device_id();
        let dummy=crate::test_support::case::name("current-user-directory-peer");
        let registration=registered["registrationId"].as_str().context("registration")?;
        crate::test_support::process::pg(&format!("INSERT INTO mdm_access.devices(tenant_id,id) VALUES('{}','{}')",case_tenant(),dummy))?;
        let manager=f.author.clone();
        let mut agent_user=Browser::default();ensure!(agent_user.login_password(&f.router,"other",crate::test_support::identity::PASSWORD).await?==StatusCode::OK);
        ensure!(agent_user.cookies["__Host-identity-session"]!=manager.cookies["__Host-identity-session"],"Agent and management must use distinct real sessions");
        f.author=agent_user.clone();
        let login=call(&f,Method::PUT,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0})),true,true).await?;
        ensure!(login.0==StatusCode::OK,"login {login:?}");
        f.author=manager;
        let search=format!("/api/v1/device-views?filter=search=icontains={}",f.author_id);
        let owner_before=owner(&mut f,None).await?;
        // Hide ownership so a current-user search cannot pass by matching the same owner.
        let mut grants=crate::test_support::identity::device_grants(Some(device),&["inventory_read"])?;
        grants.extend(crate::test_support::identity::device_grants(Some(dummy),&["inventory_read"])?);
        crate::test_support::identity::change_grants(case_tenant(),&f.author_id,grants.clone()).await?;
        let hidden=f.author.call(&f.router,Method::GET,&search,None).await?;
        ensure!(hidden.0==StatusCode::OK && hidden.1["items"].as_array().is_some_and(|items|items.is_empty()));
        let list=f.author.call(&f.router,Method::GET,"/api/v1/device-views",None).await?;
        let endpoint=list.1["items"].as_array().unwrap().iter().flat_map(|g|g["endpoints"].as_array().unwrap()).find(|e|e["id"]==device).context("endpoint")?;
        ensure!(endpoint.get("currentUser").is_none()&&endpoint.get("registrationUser").is_none());
        grants.push(crate::authorization::Grant{operation:crate::authorization::Permission::InventorySensitiveRead,scope:crate::authorization::Scope::Tenant});
        crate::test_support::identity::change_grants(case_tenant(),&f.author_id,grants.clone()).await?;
        let visible=f.author.call(&f.router,Method::GET,&search,None).await?;
        ensure!(visible.0==StatusCode::OK && visible.1["items"].as_array().is_some_and(|items|items.len()==1),"visible {visible:?}");
        let projected=visible.1["items"][0]["endpoints"][0]["currentUser"].clone();
        ensure!(projected["state"]=="active" && projected["user"]["principalId"]==f.author_id);
        let detail=f.author.call(&f.router,Method::GET,&format!("/api/v1/device-views/endpoint/{device}"),None).await?;
        ensure!(detail.0==StatusCode::OK && detail.1["endpoints"][0]["currentUser"]==projected);
        let initial=call(&f,Method::GET,None,true,false).await?;
        for key in ["revision","state","user","confirmedAt"] {ensure!(initial.1[key]==projected[key]);}
        ensure!(projected.get("display").is_some() && initial.1.get("display").is_none());
        // A stale binding cannot borrow the validity of the current registration generation.
        crate::test_support::process::pg(&format!("UPDATE mdm_access.current_users SET generation=generation+1 WHERE tenant_id='{}' AND device='{}'",case_tenant(),device))?;
        let invalid=f.author.call(&f.router,Method::GET,&search,None).await?;
        ensure!(invalid.0==StatusCode::OK && invalid.1["items"].as_array().is_some_and(|items|items.is_empty()));
        let state=call(&f,Method::GET,None,true,false).await?;
        ensure!(state.0==StatusCode::OK && state.1["state"]=="invalidated");
        f.author=agent_user.clone();
        let refreshed=call(&f,Method::PUT,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":initial.1["revision"]})),true,true).await?;
        ensure!(refreshed.0==StatusCode::OK && refreshed.1["state"]=="active");
        // Observe device revocation independently while the enterprise session remains valid.
        crate::test_support::process::pg(&format!("UPDATE mdm_access.credentials SET state='revoked' WHERE tenant_id='{}' AND registration='{}'",case_tenant(),registration))?;
        ensure!(call(&f,Method::PUT,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":refreshed.1["revision"]})),true,true).await?.0==StatusCode::UNAUTHORIZED);
        let invalid=f.author.call(&f.router,Method::GET,&format!("/api/v1/device-views/endpoint/{device}"),None).await?;
        ensure!(invalid.0==StatusCode::OK && invalid.1["endpoints"][0]["currentUser"]["state"]=="invalidated");
        // Restore fault-injected fixture state; then prove expiry is separate from active flags.
        crate::test_support::process::pg(&format!("UPDATE mdm_access.credentials SET state='active' WHERE tenant_id='{}' AND registration='{}'",case_tenant(),registration))?;
        let expiry=crate::test_support::process::pg(&format!("SELECT i.not_after FROM mdm_access.agent_issuances i JOIN mdm_access.credentials k ON(k.tenant_id,k.id)=(i.tenant_id,i.credential) WHERE k.tenant_id='{}' AND k.registration='{}'",case_tenant(),registration))?;
        crate::test_support::process::pg(&format!("UPDATE mdm_access.agent_issuances i SET not_after=extract(epoch FROM clock_timestamp())::bigint-1 FROM mdm_access.credentials k WHERE (k.tenant_id,k.id)=(i.tenant_id,i.credential) AND k.tenant_id='{}' AND k.registration='{}'",case_tenant(),registration))?;
        let expired=f.author.call(&f.router,Method::GET,&format!("/api/v1/device-views/endpoint/{device}"),None).await?;
        ensure!(expired.0==StatusCode::OK && expired.1["endpoints"][0]["currentUser"]["state"]=="invalidated");
        crate::test_support::process::pg(&format!("UPDATE mdm_access.agent_issuances i SET not_after={} FROM mdm_access.credentials k WHERE (k.tenant_id,k.id)=(i.tenant_id,i.credential) AND k.tenant_id='{}' AND k.registration='{}'",expiry.trim(),case_tenant(),registration))?;
        // A separate live management session can observe revocation of the exact Agent session.
        f.author=manager_session(&f.router).await?;
        let page=f.author.call(&f.router,Method::GET,"/api/v1/device-views?limit=1",None).await?;
        ensure!(page.0==StatusCode::OK,"page {page:?}");
        let cursor=page.1["nextCursor"].as_str().context("two authorized endpoints")?.to_owned();
        let (identity,identity_resources)=crate::test_support::identity::identity(case_tenant()).await?;
        identity_resources.finish(async {
            let session=identity.authority.inspect_session(identity.tenant,rss_identity_core::session::SessionSecret::parse(agent_user.cookies["__Host-identity-session"].clone())?,crate::identity::deadline()).await?;
            identity.authority.revoke_current_session(session,crate::identity::deadline()).await?;
            let invalid=f.author.call(&f.router,Method::GET,&format!("/api/v1/device-views/endpoint/{device}"),None).await?;
            ensure!(invalid.0==StatusCode::OK && invalid.1["endpoints"][0]["currentUser"]["state"]=="invalidated" && invalid.1["endpoints"][0]["currentUser"]["user"].is_null());
            let next=f.author.call(&f.router,Method::GET,&format!("/api/v1/device-views?limit=1&cursor={cursor}"),None).await?;
            ensure!(next.1["code"]=="device_view_cursor_invalidated","revoked cursor: {next:?}");
            let grant=f.grants.clone();
            crate::test_support::identity::change_grants(case_tenant(),&f.author_id,grant).await?;
            ensure!(owner(&mut f,None).await?["user"]==owner_before["user"]);
            Ok(())
        }).await
    }).await
}
async fn manager_session(router: &Router) -> Result<Browser> {
    let mut browser = Browser::default();
    ensure!(browser.login(router, "other").await? == StatusCode::OK);
    Ok(browser)
}
#[tokio::test]
#[ignore = "MODULE=agent.current_user: Identity management can take product authorization while directory rechecks a session"]
async fn directory_releases_product_locks_before_identity_recheck() -> Result<()> {
    use sqlx::{Connection, Executor, PgConnection};
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        f.register_profile(json!(["inventory.collect.v1"])).await?;
        ensure!(call(&f,Method::PUT,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0})),true,true).await?.0==StatusCode::OK);
        let mut grants=f.grants.clone();
        grants.push(crate::authorization::Grant{operation:crate::authorization::Permission::InventorySensitiveRead,scope:crate::authorization::Scope::Tenant});
        crate::test_support::identity::seed_grants(case_tenant(),&f.author_id,grants).await?;
        let mut authority=crate::test_support::authority::Authority::open().await?;
        let authority_resources=std::mem::take(&mut authority.resources);
        authority_resources.finish(async {
            let sessions=rss_mdm_authorization_service::session::SessionAuthority::new(authority.identity.authority.clone(),authority.identity.tenant);
            let proof=sessions.authenticate(authority.authorization.as_ref(),rss_mdm_authorization_service::credential::RequestCredential::Cookie(rss_identity_core::session::SessionSecret::parse(f.author.cookies["__Host-identity-session"].clone())?)).await?;
            let service=rss_mdm_device_service::Associations::new(authority.audit.clone(),authority.identity.tenant,&[7;32])?;
            let mut root=PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
            let mut observer=PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
            let mut hold=root.begin().await?;
            let blocker:i32=sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *hold).await?;
            sqlx::query("SELECT tenant_id FROM identity_authority.guard WHERE tenant_id=$1::uuid FOR UPDATE").bind(case_tenant()).fetch_one(&mut *hold).await?;
            let query=rss_mdm_device_service::directory::parse("limit=64")?;
            let directory_identity=authority.identity.authority.clone();
            let task=tokio::spawn(async move {
                let timer=rss_mdm_audit_integration::budget::RuntimeTimer;
                let deadline=rss_request_context::Clock::now(&timer)+Duration::from_secs(15);
                let people=rss_mdm_device_service::personnel::Reader::new(&directory_identity,deadline,&timer,None);
                service.views(&proof,&query,&people).await
            });
            let acquired=async {
                tokio::time::timeout(Duration::from_secs(5),async {
                    loop {
                        let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE '%FROM identity_authority.guard%FOR UPDATE%' AND $1=ANY(pg_blocking_pids(pid)))").bind(blocker).fetch_one(&mut observer).await?;
                        if blocked {return Ok::<_,anyhow::Error>(());}
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }).await.context("directory must reach the real Identity guard")??;
                hold.execute("SET LOCAL lock_timeout='1s'").await?;
                // This is the same lock acquired by IdentityManagementPolicy after its guard.
                rss_mdm_authorization_service::lock_on(&mut hold,case_tenant(),crate::test_support::identity::INSTANCE).await?;
                Ok::<_,anyhow::Error>(())
            }.await;
            hold.rollback().await?;
            let page=task.await?;
            let page=page.context("directory failed while exercising the Identity guard")?;
            acquired.context("directory retained product locks while waiting for Identity")?;
            ensure!(page["items"][0]["endpoints"][0]["currentUser"]["state"]=="active");
            root.close().await?;
            observer.close().await?;
            Ok(())
        }).await
    }).await
}

#[tokio::test]
#[ignore = "MODULE=agent.current_user: GET releases device locks for logout while Identity waits, then rejects its stale binding"]
async fn agent_read_releases_device_lock_and_rejects_concurrent_logout() -> Result<()> {
    use sqlx::{Connection, PgConnection};
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        f.register_profile(json!(["inventory.collect.v1"])).await?;
        let login=call(&f,Method::PUT,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0})),true,true).await?;
        ensure!(login.0==StatusCode::OK);
        let options=crate::device::test_support::options("postgres")?;
        let mut root=PgConnection::connect_with(&options).await?;
        let mut observer=PgConnection::connect_with(&options).await?;
        let mut hold=root.begin().await?;
        let blocker:i32=sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *hold).await?;
        sqlx::query("SELECT tenant_id FROM identity_authority.guard WHERE tenant_id=$1::uuid FOR UPDATE").bind(case_tenant()).fetch_one(&mut *hold).await?;
        let router=f.router.clone();
        let pending=tokio::spawn(async move {
            let request=Request::builder().method(Method::GET).uri(CURRENT).header("host","mdm.example.test:9445").extension(evidence(crate::test_support::agent_execution::case_credential()).unwrap()).body(Body::empty())?;
            let response=router.oneshot(request).await?;
            let status=response.status();
            let bytes=response.into_body().collect().await?.to_bytes();
            Ok::<_,anyhow::Error>((status,serde_json::from_slice::<Value>(&bytes)?))
        });
        let changed=async {
            tokio::time::timeout(Duration::from_secs(5),async {
                loop {
                    let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE '%FROM identity_authority.guard%FOR UPDATE%' AND $1=ANY(pg_blocking_pids(pid)))").bind(blocker).fetch_one(&mut observer).await?;
                    if waiting {return Ok::<_,anyhow::Error>(());}
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await.context("Agent GET must reach the real Identity guard")??;
            // Identity management can own auth while device lifecycle waits for the same device.
            rss_mdm_authorization_service::lock_on(&mut hold,case_tenant(),crate::test_support::identity::INSTANCE).await?;
            let logout=tokio::time::timeout(Duration::from_secs(3),call(&f,Method::DELETE,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":login.1["revision"]})),true,false)).await.context("logout blocked behind the GET's device lock")??;
            ensure!(logout.0==StatusCode::OK,"logout must settle while GET awaits Identity: {logout:?}");
            Ok::<_,anyhow::Error>(())
        }.await;
        hold.rollback().await?;
        let read=pending.await??;
        changed?;
        ensure!(read.0==StatusCode::CONFLICT,"GET returned a superseded binding: {read:?}");
        let current=call(&f,Method::GET,None,true,false).await?;
        ensure!(current.0==StatusCode::OK&&current.1["state"]=="unbound"&&current.1["revision"]==2);
        observer.close().await?;root.close().await?;
        Ok(())
    }).await
}
