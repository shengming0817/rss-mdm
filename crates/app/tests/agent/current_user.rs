//! Device mTLS and the existing enterprise session jointly bind the current user.
use crate::test_support::{agent::*, agent_execution::Fixture, runtime::*, *};
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
        f.author=crate::test_support::authority::Authority::prepared_browser("admin").await?;
        let admin=crate::test_support::http::browser_subject(&f.author,&f.router).await?;
        crate::test_support::identity::set_grants(case_tenant(),&admin,f.grants.clone()).await?;
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
